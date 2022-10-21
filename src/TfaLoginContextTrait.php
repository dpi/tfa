<?php

namespace Drupal\tfa;

use Psr\Log\LoggerInterface;
use Drupal\Core\Url;

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
   * Tfa plugin manager.
   *
   * @var \Drupal\tfa\TfaPluginManager
   */
  protected $tfaPluginManager;

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
   * Array of login plugins.
   *
   * @var \Drupal\tfa\Plugin\TfaLoginInterface[]
   */
  protected $tfaLoginPlugins;

  /**
   * The private temporary store.
   *
   * @var \Drupal\Core\TempStore\PrivateTempStore
   */
  protected $privateTempStore;

  /**
   * Set the user object.
   */
  public function setUser($uid) {
    $this->user = $this->userStorage->load($uid);

    $this->tfaLoginPlugins = [];
    $login_definitions = $this->tfaPluginManager->getLoginDefinitions();
    if (!empty($login_definitions)) {
      foreach ($login_definitions as $plugin_id => $definition) {
        $this->tfaLoginPlugins[] = $this->tfaPluginManager->createInstance($plugin_id, ['uid' => $uid]);
      }
    }
    // If possible, set up an instance of tfaValidationPlugin and the user's
    // list of plugins.
    $validation_plugin = $this->tfaSettings->get('default_validation_plugin');
    if (!empty($validation_plugin)) {
      $this->tfaValidationPlugin = $this->tfaPluginManager->createInstance($validation_plugin, ['uid' => $uid]);
    }
    else {
      $this->tfaValidationPlugin = NULL;
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
   * Can the user skip tfa on password reset?
   *
   * @return bool
   *   TRUE if the user can skip tfa.
   */
  public function canResetPassSkip() {
    return $this->tfaSettings->get('reset_pass_skip_enabled') && ((int) $this->getUser()->id() === 1);
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
    $user_tfa_data = $this->tfaGetTfaData($this->getUser()->id());
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

    $user_tfa_data = $this->tfaGetTfaData($this->getUser()->id());
    $validation_skipped = $user_tfa_data['validation_skipped'] ?? 0;
    return max(0, $allowed_skips - $validation_skipped);
  }

  /**
   * Increment the count of $this->getUser() logins without setting up TFA.
   */
  public function hasSkipped() {
    $user_tfa_data = $this->tfaGetTfaData($this->getUser()->id());
    $validation_skipped = $user_tfa_data['validation_skipped'] ?? 0;
    $user_tfa_data['validation_skipped'] = $validation_skipped + 1;
    $this->tfaSaveTfaData($this->getUser()->id(), $user_tfa_data);
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

  /**
   * Store UID in the temporary store.
   *
   * @param string|int $uid
   *   User id to store.
   */
  public function tempStoreUid($uid) {
    $this->privateTempStore->set('tfa-entry-uid', $uid);
  }

  /**
   * Check if the user can login without TFA.
   *
   * @return bool
   *   Return true if the user can login without TFA,
   *   otherwise return false.
   */
  public function canLoginWithoutTfa(LoggerInterface $logger) {
    // User may be able to skip TFA, depending on module settings and number of
    // prior attempts.
    $remaining = $this->remainingSkips();
    $user = $this->getUser();
    if ($remaining) {
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
      // User can login without TFA.
      return TRUE;
    }
    else {
      $message = $this->config('tfa.settings')->get('help_text');
      $this->messenger()->addError($message);
      $logger->notice('@name has no more remaining attempts for bypassing the second authentication factor.', ['@name' => $user->getAccountName()]);
    }

    // User can't login without TFA.
    return FALSE;
  }

}
