<?php

declare(strict_types=1);

namespace Drupal\tfa_test_encryption\Plugin\EncryptionMethod;

use Drupal\encrypt\EncryptionMethodInterface;
use Drupal\encrypt\Exception\EncryptException;
use Drupal\encrypt\Plugin\EncryptionMethod\EncryptionMethodBase;

/**
 * A failing test encryption method.
 *
 * @EncryptionMethod(
 *   id = \Drupal\tfa_test_encryption\Plugin\EncryptionMethod\FailingEncryption::PLUGIN_ID,
 *   title = @Translation("A failing test encryption method"),
 *   description = "A failing test encryption method.",
 *   key_type = {"encryption"}
 * )
 */
final class FailingEncryption extends EncryptionMethodBase implements EncryptionMethodInterface {

  const PLUGIN_ID = 'tfa_test_encryption_failing_encryption';

  /**
   * {@inheritdoc}
   */
  public function checkDependencies($text = NULL, $key = NULL) {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function encrypt($text, $key, $options = []) {
    throw new EncryptException('Failed to encrypt!');
  }

  /**
   * {@inheritdoc}
   */
  public function decrypt($text, $key, $options = []) {
    throw new EncryptException('Failed to decrypt');
  }

}
