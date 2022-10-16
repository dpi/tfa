<?php

namespace Drupal\tfa;

/**
 * Provides methods to save tfa user settings.
 */
trait TfaUserDataTrait {

  /**
   * The user data service.
   *
   * @var \Drupal\user\UserDataInterface
   */
  protected $userData;

  /**
   * Store user specific information.
   *
   * @param string $module
   *   The name of the module the data is associated with.
   * @param array $data
   *   The value to store. Non-scalar values are serialized automatically.
   * @param int $uid
   *   The user id.
   */
  protected function setUserData($module, array $data, $uid) {
    $this->userData->set(
      $module,
      $uid,
      key($data),
      current($data)
    );
  }

  /**
   * Returns data stored for the current validated user account.
   *
   * @param string $module
   *   The name of the module the data is associated with.
   * @param string $key
   *   The name of the data key.
   * @param int $uid
   *   The user id.
   *
   * @return mixed|array
   *   The stored value is returned, or NULL if no value was found.
   */
  protected function getUserData($module, $key, $uid) {
    return $this->userData->get($module, $uid, $key);
  }

  /**
   * Deletes data stored for the current validated user account.
   *
   * @param string $module
   *   The name of the module the data is associated with.
   * @param string $key
   *   The name of the data key.
   * @param int $uid
   *   The user id.
   */
  protected function deleteUserData($module, $key, $uid) {
    $this->userData->delete($module, $uid, $key);
  }

  /**
   * Save TFA data for an account.
   *
   * The data like status of tfa, timestamp of last activation
   * or deactivation etc. is stored here.
   *
   * @param int $uid
   *   The user id.
   * @param array $data
   *   Data to be saved.
   */
  public function tfaSaveTfaData($uid, array $data = []) {
    // Check if existing data and update.
    $existing = $this->tfaGetTfaData($uid);

    if (isset($existing['validation_skipped']) && !isset($data['validation_skipped'])) {
      $validation_skipped = $existing['validation_skipped'];
    }
    else {
      $validation_skipped = $data['validation_skipped'] ?? 0;
    }

    if (!empty($existing['data'])) {
      $tfa_data = $existing['data'];
    }
    else {
      $tfa_data = [
        'plugins' => [],
        'sms' => FALSE,
      ];
    }
    if (isset($data['plugins'])) {
      $tfa_data['plugins'][$data['plugins']] = $data['plugins'];
    }
    if (isset($data['sms'])) {
      $tfa_data['sms'] = $data['sms'];
    }

    $status = 1;
    if (isset($data['status']) && $data['status'] === FALSE) {
      $tfa_data = [];
      $status = 0;
    }

    $record = [
      'saved' => \Drupal::time()->getRequestTime(),
      'status' => $status,
      'data' => $tfa_data,
      'validation_skipped' => $validation_skipped,
    ];

    $this->userData->set('tfa', $uid, 'tfa_user_settings', $record);
  }

  /**
   * Get TFA data for an account.
   *
   * @param int $uid
   *   User account id.
   *
   * @return array
   *   TFA data.
   */
  protected function tfaGetTfaData($uid) {
    $result = $this->userData->get('tfa', $uid, 'tfa_user_settings');

    if (!empty($result)) {
      $result['status'] = ($result['status'] == '1');
      return $result;
    }
    return [];
  }

}
