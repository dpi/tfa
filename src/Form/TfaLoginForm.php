<?php

namespace Drupal\tfa\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\tfa\TfaLoginContextTrait;
use Drupal\tfa\TfaLoginTrait;
use Drupal\user\Form\UserLoginForm;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * TFA user login form.
 *
 * @noinspection PhpInternalEntityUsedInspection
 */
class TfaLoginForm extends UserLoginForm {
  use TfaLoginContextTrait;
  use TfaLoginTrait;

  /**
   * Redirect destination service.
   *
   * @var \Drupal\Core\Routing\RedirectDestinationInterface
   */
  protected $destination;

  /**
   * The private temporary store.
   *
   * @var \Drupal\Core\TempStore\PrivateTempStore
   */
  protected $privateTempStore;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $instance = parent::create($container);

    $instance->tfaValidationManager = $container->get('plugin.manager.tfa.validation');
    $instance->tfaLoginManager = $container->get('plugin.manager.tfa.login');
    $instance->tfaSettings = $container->get('config.factory')->get('tfa.settings');

    $instance->userData = $container->get('user.data');

    $instance->destination = $container->get('redirect.destination');
    $instance->privateTempStore = $container->get('tempstore.private')->get('tfa');

    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $form = parent::buildForm($form, $form_state);
    $form['#submit'][] = '::tfaLoginFormRedirect';
    $form['#cache'] = ['max-age' => 0];

    return $form;
  }

  /**
   * Login submit handler.
   *
   * Determine if TFA process applies. If not, call the parent form submit.
   *
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // The user ID must not be NULL.
    if (empty($uid = $form_state->get('uid'))) {
      return;
    }

    // Similar to tfa_user_login() but not required to force user logout.
    /** @var \Drupal\user\UserInterface $user */
    $user = $this->userStorage->load($uid);
    $this->setUser($user);

    /* Uncomment when things go wrong and you get logged out.
    user_login_finalize($user);
    $form_state->setRedirect('<front>');
    return;
     */

    // Stop processing if Tfa is not enabled.
    if ($this->isTfaDisabled()) {
      parent::submitForm($form, $form_state);
    }
    else {
      // Setup TFA.
      if ($this->isReady()) {
        $this->loginWithTfa($form_state);
      }
      else {
        $this->loginWithoutTfa($form_state);
      }
    }
  }

  /**
   * Handle login when TFA is set up for the user.
   *
   * If any of the TFA plugins allows login, then finalize the login. Otherwise,
   * set a redirect to enter a second factor.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The state of the login form.
   */
  public function loginWithTfa(FormStateInterface $form_state) {
    $user = $this->getUser();
    if ($this->pluginAllowsLogin()) {
      $this->doUserLogin();
      $this->messenger()->addStatus($this->t('You have logged in on a trusted browser.'));
      $form_state->setRedirect('<front>');
    }
    else {
      // Begin TFA and set process context.
      if (!empty($this->getRequest()->query->get('destination'))) {
        $parameters = $this->destination->getAsArray();
        $this->getRequest()->query->remove('destination');
      }
      else {
        $parameters = [];
      }
      $parameters['uid'] = $user->id();
      $parameters['hash'] = $this->getLoginHash($user);
      $form_state->setRedirect('tfa.entry', $parameters);

      // Store UID in order to later verify access to entry form.
      $this->privateTempStore->set('tfa-entry-uid', $user->id());
    }
  }

  /**
   * Handle the case where TFA is not yet set up.
   *
   * If the user has any remaining logins, then finalize the login with a
   * message to set up TFA. Otherwise, leave the user logged out.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The state of the login form.
   */
  public function loginWithoutTfa(FormStateInterface $form_state) {
    // User may be able to skip TFA, depending on module settings and number of
    // prior attempts.
    $remaining = $this->remainingSkips();
    if ($remaining) {
      $user = $this->getUser();
      $tfa_setup_link = Url::fromRoute('tfa.overview', [
        'user' => $user->id(),
      ])->toString();
      $message = $this->formatPlural(
        $remaining - 1,
        'You are required to <a href="@link">setup two-factor authentication</a>. You have @remaining attempt left. After this you will be unable to login.',
        'You are required to <a href="@link">setup two-factor authentication</a>. You have @remaining attempts left. After this you will be unable to login.',
        ['@remaining' => $remaining - 1, '@link' => $tfa_setup_link]
      );
      $this->messenger()->addError($message);
      $this->hasSkipped();
      $this->doUserLogin();
      $form_state->setRedirect('<front>');
    }
    else {
      $message = $this->config('tfa.settings')->get('help_text');
      $this->messenger()->addError($message);
      $this->logger('tfa')->notice('@name has no more remaining attempts for bypassing the second authentication factor.', ['@name' => $this->getUser()->getAccountName()]);
    }
  }

  /**
   * Login submit handler for TFA form redirection.
   *
   * Should be last invoked form submit handler for forms user_login and
   * user_login_block so that when the TFA process is applied the user will be
   * sent to the TFA form.
   *
   * @param array $form
   *   The current form api array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current form state.
   */
  public function tfaLoginFormRedirect(array $form, FormStateInterface $form_state) {
    $route = $form_state->getValue('tfa_redirect');
    if (isset($route)) {
      $form_state->setRedirect($route);
    }
  }

}
