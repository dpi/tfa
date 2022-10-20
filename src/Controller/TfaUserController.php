<?php

namespace Drupal\tfa\Controller;

use Drupal\Component\Utility\Crypt;
use Drupal\Core\Url;
use Drupal\tfa\TfaLoginContextTrait;
use Drupal\tfa\TfaLoginTrait;
use Drupal\user\Controller\UserController;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Drupal\user\UserInterface;

/**
 * Provide controller routines for user routes.
 */
class TfaUserController extends UserController {
  use TfaLoginContextTrait;
  use TfaLoginTrait;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $instance = parent::create($container);

    $instance->tfaLoginManager = $container->get('plugin.manager.tfa.login');
    $instance->tfaValidationManager = $container->get('plugin.manager.tfa.validation');
    $instance->tfaSettings = $container->get('config.factory')->get('tfa.settings');

    $instance->userData = $container->get('user.data');

    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function resetPassLogin($uid, $timestamp, $hash, Request $request) {
    $this->setUser($uid);
    /** @var \Drupal\user\UserInterface $user */
    $user = $this->getUser();

    // Let Drupal core deal with the one time login,
    // if Tfa is not enabled
    // or current user can skip TFA while resetting password.
    if (!$this->isModuleSetup() || !$this->isTfaRequired() || $this->canResetPassSkip()) {
      // Let the Drupal core to validate the one time login.
      return parent::resetPassLogin($uid, $timestamp, $hash, $request);
    }
    else {
      // Whether the TFA Validation Plugin is set and ready for use.
      $tfa_ready = $this->isReady();
      // Check for authentication plugin.
      if ($tfa_ready && $this->pluginAllowsLogin()) {
        // A trused browser or at least one plugin allows authentication.
        $this->messenger()->addStatus($this->t('You have logged in on a trusted browser.'));
        // Let the Drupal core to validate the one time login.
        return parent::resetPassLogin($uid, $timestamp, $hash, $request);
      }

      // Drupal doesn't provide a hook or event
      // in which TFA can implement the TFA validation,
      // before the user_login_finalize() is called.
      // @see https://git.drupalcode.org/project/drupal/-/blob/9.4.6/core/modules/user/src/Controller/UserController.php#L245
      // So borrow following codes from the core
      // \Drupal\user\Controller\UserController::resetPassLogin(),
      $current = \Drupal::time()->getRequestTime();

      // Verify that the user exists and is active.
      if ($user === NULL || !$user->isActive()) {
        // Blocked or invalid user ID, so deny access. The parameters will be in
        // the watchdog's URL for the administrator to check.
        throw new AccessDeniedHttpException();
      }

      // Time out, in seconds, until login URL expires.
      $timeout = $this->config('user.settings')->get('password_reset_timeout');
      // No time out for first time login.
      if ($user->getLastLoginTime() && $current - $timestamp > $timeout) {
        $this->messenger()->addError($this->t('You have tried to use a one-time login link that has expired. Please request a new one using the form below.'));
        return $this->redirect('user.pass');
      }
      elseif ($user->isAuthenticated() && ($timestamp >= $user->getLastLoginTime()) && ($timestamp <= $current) && hash_equals($hash, user_pass_rehash($user, $timestamp))) {
        // The one time login has been validated.
        // Check if TFA is set up for this user.
        if ($tfa_ready) {
          // TFA is set up.
          // Let the user's password be changed without the current password
          // check.
          $token = Crypt::randomBytesBase64(55);
          $request->getSession()->set('pass_reset_' . $uid, $token);
          // Begin TFA and set process context.
          // @todo This is used in send plugins which has not been implemented yet.
          // $this->begin($tfaValidationPlugin);
          // Log the one-time login link attempts.
          $this->logger->notice('User %name used one-time login link at time %timestamp.', [
            '%name' => $user->getDisplayName(),
            '%timestamp' => $timestamp,
          ]);
          // Redirect to TFA entry form.
          return $this->redirect('tfa.entry', [
            'uid' => $uid,
            'hash' => $this->getLoginHash($user),
          ], [
            'query' => ['pass-reset-token' => $token],
            'absolute' => TRUE,
          ]);
        }
        else {
          // TFA is not set up yet.
          // User may be able to skip TFA,
          // depending on module settings and number of
          // prior attempts.
          $remaining = $this->remainingSkips();

          if ($remaining) {
            // User still can skip the TFA
            // as the attempts hasn't exceeded the number in settings.
            // TFA setup link.
            $tfa_setup_link = Url::fromRoute('tfa.overview', ['user' => $uid])->toString();
            // Reminder message.
            $message = $this->formatPlural(
                $remaining - 1,
                'You are required to <a href="@link">setup two-factor authentication</a>. You have @remaining attempt left. After this you will be unable to login.',
                'You are required to <a href="@link">setup two-factor authentication</a>. You have @remaining attempts left. After this you will be unable to login.',
                [
                  '@remaining' => $remaining - 1,
                  '@link' => $tfa_setup_link,
                ]);
            $this->messenger()->addError($message);
            // Increment the count of logins without TFA.
            $this->hasSkipped();
            // TFA is skipped.
            // Redirect to user edit form.
            return $this->redirectToUserForm($user, $request, $timestamp);
          }
          else {
            // User can't skip the TFA.
            $message = $this->config('tfa.settings')->get('help_text');
            $this->messenger()->addError($message);
            $this->getLogger('tfa')->notice('@name has no more remaining attempts for bypassing the second authentication factor.', [
              '@name' => $user->getAccountName(),
            ]);
            // TFA validation failed.
            // Redirect to the home page.
            return $this->redirect('<front>');
          }
        }
      }
    }

    return parent::resetPassLogin($uid, $timestamp, $hash, $request);
  }

  /**
   * Redirect to user edit form.
   *
   * @param \Drupal\user\UserInterface $user
   *   Current user.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   Controller request.
   * @param int $timestamp
   *   The current timestamp.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   Recirect response to user eidt form.
   */
  protected function redirectToUserForm(UserInterface $user, Request $request, $timestamp) {
    user_login_finalize($user);
    $this->logger->notice('User %name used one-time login link at time %timestamp.', [
      '%name' => $user->getDisplayName(),
      '%timestamp' => $timestamp,
    ]);
    $this->messenger()->addStatus($this->t('You have just used your one-time login link. It is no longer necessary to use this link to log in. Please change your password.'));
    // Let the user's password be changed without the current password
    // check.
    $token = Crypt::randomBytesBase64(55);
    $request->getSession()->set('pass_reset_' . $user->id(), $token);
    // Clear any flood events for this user.
    $this->flood->clear('user.password_request_user', $user->id());

    return $this->redirect('entity.user.edit_form', ['user' => $user->id()], [
      'query' => ['pass-reset-token' => $token],
      'absolute' => TRUE,
    ]);
  }

}
