<?php

namespace Drupal\tfa\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\tfa\Plugin\TfaSendInterface;
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
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $instance = parent::create($container);
    $instance->tfaPluginManager = $container->get('plugin.manager.tfa');
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
    $this->setUser($uid);

    /* Uncomment when things go wrong and you get logged out.
    user_login_finalize($user);
    $form_state->setRedirect('<front>');
    return;
     */

    // Stop processing if Tfa is not enabled.
    if (!$this->isModuleSetup() || !$this->isTfaRequired()) {
      parent::submitForm($form, $form_state);
    }
    else {
      // Setup TFA.
      if ($this->isReady()) {
        $this->loginWithTfa($form_state);
      }
      else {
        if ($this->canLoginWithoutTfa($this->logger('tfa'))) {
          $this->doUserLogin();
          $form_state->setRedirect('<front>');
        }
        else {
          $this->logger('tfa')->notice();
        }
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
  protected function loginWithTfa(FormStateInterface $form_state) {
    $user = $this->getUser();
    if ($this->pluginAllowsLogin()) {
      $this->doUserLogin();
      $this->messenger()->addStatus($this->t('You have logged in on a trusted browser.'));
      $form_state->setRedirect('<front>');
    }
    else {
      // Begin TFA and set process context.
      // @todo This is used in send plugins which has not been implemented yet.
      // $this->begin($tfaValidationPlugin);
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
      $this->tempStoreUid($user->id());
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

  /**
   * Begin the TFA process.
   *
   * @param \Drupal\tfa\Plugin\TfaSendInterface $tfaSendPlugin
   *   The send plugin instance.
   */
  protected function begin(TfaSendInterface $tfaSendPlugin) {
    // Invoke begin method on send validation plugins.
    if (method_exists($tfaSendPlugin, 'begin')) {
      $tfaSendPlugin->begin();
    }
  }

}
