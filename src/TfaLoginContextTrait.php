<?php

namespace Drupal\tfa;

use Drupal\Component\Plugin\Exception\PluginException;
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
   * Validation plugin manager.
   *
   * @var \Drupal\tfa\TfaValidationPluginManager
   */
  protected $tfaValidationManager;

  /**
   * Login plugin manager.
   *
   * @var \Drupal\tfa\TfaLoginPluginManager
   */
  protected $tfaLoginManager;

  /**
   * Tfa settings config object.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $tfaSettings;

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
    // Global TFA settings take precedence.
    if (!($this->tfaSettings->get('enabled')) || empty($this->tfaSettings->get('default_validation_plugin'))) {
      return TRUE;
    }

    // Check if the user has enabled TFA.
    $user_tfa_data = $this->tfaGetTfaData($this->user->id(), $this->userData);
    if (!empty($user_tfa_data['status']) && !empty($user_tfa_data['data']['plugins'])) {
      return FALSE;
    }

    // TFA is not necessary if the user doesn't have one of the required roles.
    $required_roles = array_filter($this->tfaSettings->get('required_roles'));
    return empty(array_intersect($required_roles, $this->user->getRoles()));
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
      try {
        /** @var \Drupal\tfa\Plugin\TfaValidationInterface $validation_plugin */
        $validation_plugin = $this->tfaValidationManager->createInstance($default_validation_plugin, ['uid' => $this->user->id()]);
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

    $user_tfa_data = $this->tfaGetTfaData($this->user->id(), $this->userData);
    $validation_skipped = $user_tfa_data['validation_skipped'] ?? 0;
    return max(0, $allowed_skips - $validation_skipped);
  }

  /**
   * Increment the count of user logins without setting up TFA.
   */
  public function hasSkipped() {
    $user_tfa_data = $this->tfaGetTfaData($this->user->id(), $this->userData);
    $validation_skipped = $user_tfa_data['validation_skipped'] ?? 0;
    $user_tfa_data['validation_skipped'] = $validation_skipped + 1;
    $this->tfaSaveTfaData($this->user->id(), $this->userData, $user_tfa_data);
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
    /** @var \Drupal\tfa\Plugin\TfaLoginInterface[] $login_plugins */
    try {
      $login_plugins = $this->tfaLoginManager->getPlugins(['uid' => $this->user->id()]);
    }
    catch (PluginException $e) {
      return FALSE;
    }
    if (!empty($login_plugins)) {
      foreach ($login_plugins as $plugin) {
        if ($plugin->loginAllowed()) {
          return TRUE;
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
