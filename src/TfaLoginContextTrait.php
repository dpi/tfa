<?php

namespace Drupal\tfa;

use Drupal\Component\Plugin\Exception\PluginException;
use Drupal\tfa\Event\TfaUserHasTfaEvent;
use Drupal\user\UserInterface;

/**
 * Provide context for the current login attempt.
 *
 * This trait collects data needed to decide whether TFA is required and, if so,
 * whether it is successful. This includes configuration of the module, the
 * current request, and the user that is attempting to log in.
 *
 * The methods defined in this trait require that the user property is defined,
 * so make sure to call the setUser method before using any other method here.
 *
 * @internal
 */
trait TfaLoginContextTrait {
  use TfaUserDataTrait;

  /**
   * Tfa plugin manager.
   *
   * @var \Drupal\tfa\TfaPluginManager
   */
  protected $tfaPluginManager;

  /**
   * Tfa settings config object.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $tfaSettings;

  /**
   * The event dispatcher.
   *
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  protected $eventDispatcher;

  /**
   * Entity for the user that is attempting to login.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $user;

  /**
   * Set the user object.
   *
   * @param \Drupal\user\UserInterface $user
   *   The entity object of the user attempting to log in.
   */
  public function setUser(UserInterface $user) {
    $this->user = $user;
  }

  /**
   * Get the user object.
   *
   * @return \Drupal\user\UserInterface
   *   The entity object of the user attempting to log in.
   */
  public function getUser() {
    return $this->user;
  }

  /**
   * Is TFA enabled and configured?
   *
   * @return bool
   *   TRUE if TFA is disabled.
   */
  public function isTfaDisabled() {
    $event = TfaUserHasTfaEvent::create($this->getUser());
    $this->eventDispatcher->dispatch($event);
    return FALSE === $event->isEnforcingTfa();
  }

  /**
   * Check whether the Validation Plugin is set and ready for use.
   *
   * @return bool
   *   TRUE if Validation Plugin exists and is ready for use.
   */
  public function isReady() {
    // If possible, set up an instance of tfaValidationPlugin and the user's
    // list of plugins.
    $default_validation_plugin = $this->tfaSettings->get('default_validation_plugin');
    if (!empty($default_validation_plugin)) {
      /** @var \Drupal\tfa\Plugin\TfaValidationInterface $validation_plugin */
      try {
        $validation_plugin = $this->tfaPluginManager->createInstance($default_validation_plugin, ['uid' => $this->user->id()]);
        if (isset($validation_plugin) && $validation_plugin->ready()) {
          return TRUE;
        }
      }
      catch (PluginException $e) {
        return FALSE;
      }
    }

    return FALSE;
  }

  /**
   * Remaining number of allowed logins without setting up TFA.
   *
   * @return int|false
   *   FALSE if users are never allowed to log in without setting up TFA.
   *   The remaining number of times user may log in without setting up TFA.
   */
  public function remainingSkips() {
    $allowed_skips = intval($this->tfaSettings->get('validation_skip'));
    // Skipping TFA setup is not allowed.
    if (!$allowed_skips) {
      return FALSE;
    }

    $user_tfa_data = $this->tfaGetTfaData($this->user->id());
    $validation_skipped = $user_tfa_data['validation_skipped'] ?? 0;
    return max(0, $allowed_skips - $validation_skipped);
  }

  /**
   * Increment the count of user logins without setting up TFA.
   */
  public function hasSkipped() {
    $user_tfa_data = $this->tfaGetTfaData($this->user->id());
    $validation_skipped = $user_tfa_data['validation_skipped'] ?? 0;
    $user_tfa_data['validation_skipped'] = $validation_skipped + 1;
    $this->tfaSaveTfaData($this->user->id(), $user_tfa_data);
  }

  /**
   * Whether at least one plugin allows authentication.
   *
   * If any plugin returns TRUE then authentication is not interrupted by TFA.
   *
   * @return bool
   *   TRUE if login allowed otherwise FALSE.
   */
  public function pluginAllowsLogin() {
    $login_definitions = $this->tfaPluginManager->getLoginDefinitions();
    if (!empty($login_definitions)) {
      foreach ($login_definitions as $plugin_id => $definition) {
        /** @var \Drupal\tfa\Plugin\TfaLoginInterface $login_plugin */
        try {
          $login_plugin = $this->tfaPluginManager->createInstance($plugin_id, ['uid' => $this->user->id()]);
          if (isset($login_plugin) && $login_plugin->loginAllowed()) {
            return TRUE;
          }
        }
        catch (PluginException $e) {
          continue;
        }
      }
    }

    return FALSE;
  }

  /**
   * Wrapper for user_login_finalize().
   */
  public function doUserLogin() {
    // @todo Set a hash mark to indicate TFA authorization has passed.
    user_login_finalize($this->user);
  }

}
