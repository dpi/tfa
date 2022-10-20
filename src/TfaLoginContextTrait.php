<?php

namespace Drupal\tfa;

/**
 * Provide context for the current login attempt.
 *
 * This class collects data needed to decide whether TFA is required and, if so,
 * whether it is successful. This includes configuration of the module, the
 * current request, and the user that is attempting to log in.
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
   * The tfaValidation plugin.
   *
   * @var \Drupal\tfa\Plugin\TfaValidationInterface|null
   */
  protected $tfaValidationPlugin;

  /**
   * Tfa settings config object.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $tfaSettings;

  /**
   * The user storage.
   *
   * @var \Drupal\user\UserStorageInterface
   */
  protected $userStorage;

  /**
   * Entity for the user that is attempting to login.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $user;

  /**
   * Array of login plugins for a given user.
   *
   * @var \Drupal\tfa\Plugin\TfaLoginInterface[]
   */
  protected $userLoginPlugins;

  /**
   * Array of login plugins.
   *
   * @var \Drupal\tfa\Plugin\TfaLoginInterface[]
   */
  protected $tfaLoginPlugins;

  /**
   * Set the user object.
   */
  public function setUser($uid) {
    $this->user = $this->userStorage->load($uid);

    $this->tfaLoginPlugins = $this->tfaLoginManager->getPlugins(['uid' => $uid]);
    // If possible, set up an instance of tfaValidationPlugin and the user's
    // list of plugins.
    $validationPluginName = $this->tfaSettings->get('default_validation_plugin');
    if (!empty($validationPluginName)) {
      $this->tfaValidationPlugin = $this->tfaValidationManager
        ->createInstance($validationPluginName, ['uid' => $uid]);
      $this->userLoginPlugins = $this->tfaLoginManager
        ->getPlugins(['uid' => $uid]);
    }
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
   *   Whether or not the TFA module is configured for use.
   */
  public function isModuleSetup() {
    return intval($this->tfaSettings->get('enabled')) && !empty($this->tfaSettings->get('default_validation_plugin'));
  }

  /**
   * Check whether $this->getUser() is required to use TFA.
   *
   * @return bool
   *   TRUE if $this->getUser() is required to use TFA.
   */
  public function isTfaRequired() {
    // If TFA has been set up for the user, then it is required.
    $user_tfa_data = $this->tfaGetTfaData($this->getUser()->id(), $this->userData);
    if (!empty($user_tfa_data['status']) && !empty($user_tfa_data['data']['plugins'])) {
      return TRUE;
    }

    // If the user has a role that is required to use TFA, then return TRUE.
    $required_roles = array_filter($this->tfaSettings->get('required_roles'));
    $user_roles = $this->getUser()->getRoles();
    return (bool) array_intersect($required_roles, $user_roles);
  }

  /**
   * Check whether the Validation Plugin is set and ready for use.
   *
   * @return bool
   *   TRUE if Validation Plugin exists and is ready for use.
   */
  public function isReady() {
    return isset($this->tfaValidationPlugin) && $this->tfaValidationPlugin->ready();
  }

  /**
   * Remaining number of allowed logins without setting up TFA.
   *
   * @return int|false
   *   FALSE if users are never allowed to log in without setting up TFA.
   *   The remaining number of times $this->getUser() may log in without setting
   *   up TFA.
   */
  public function remainingSkips() {
    $allowed_skips = intval($this->tfaSettings->get('validation_skip'));
    // Skipping TFA setup is not allowed.
    if (!$allowed_skips) {
      return FALSE;
    }

    $user_tfa_data = $this->tfaGetTfaData($this->getUser()->id(), $this->userData);
    $validation_skipped = $user_tfa_data['validation_skipped'] ?? 0;
    return max(0, $allowed_skips - $validation_skipped);
  }

  /**
   * Increment the count of $this->getUser() logins without setting up TFA.
   */
  public function hasSkipped() {
    $user_tfa_data = $this->tfaGetTfaData($this->getUser()->id(), $this->userData);
    $validation_skipped = $user_tfa_data['validation_skipped'] ?? 0;
    $user_tfa_data['validation_skipped'] = $validation_skipped + 1;
    $this->tfaSaveTfaData($this->getUser()->id(), $this->userData, $user_tfa_data);
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
    if (!empty($this->tfaLoginPlugins)) {
      foreach ($this->tfaLoginPlugins as $plugin) {
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
    user_login_finalize($this->getUser());
  }

}
