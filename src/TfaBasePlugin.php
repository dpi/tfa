<?php

namespace Drupal\tfa;

use Drupal\Component\Plugin\PluginBase;
use Drupal\Component\Utility\Crypt;
use Drupal\Core\DependencyInjection\DependencySerializationTrait;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Site\Settings;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Base class for tfa plugins.
 */
abstract class TfaBasePlugin extends PluginBase implements TfaPluginInterface, ContainerFactoryPluginInterface {
  use DependencySerializationTrait;
  use StringTranslationTrait;
  use TfaUserDataTrait;

  /**
   * The error for the current validation.
   *
   * @var string[]
   */
  protected $errorMessages;

  /**
   * The allowed code length.
   *
   * @var int
   */
  protected $codeLength;

  /**
   * The user id.
   *
   * @var int
   */
  protected $uid;

  /**
   * Whether the code has been used before.
   *
   * @var string
   */
  protected $alreadyAccepted;

  /**
   * {@inheritdoc}
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);

    // Default code length is 6.
    $this->codeLength = 6;

    $this->uid = $this->configuration['uid'];
    $this->alreadyAccepted = FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getLabel() {
    // Cast the label to a string since it is a TranslatableMarkup object.
    return (string) $this->pluginDefinition['label'];
  }

  /**
   * {@inheritdoc}
   */
  public function getHelpLinks() {
    return $this->pluginDefinition['helpLinks'];
  }

  /**
   * {@inheritdoc}
   */
  public function getSetupMessages() {
    return ($this->pluginDefinition['setupMessages']) ?: '';
  }

  /**
   * Get error messages suitable for form_set_error().
   *
   * @return array
   *   An array of error strings.
   */
  public function getErrorMessages() {
    return $this->errorMessages;
  }

  /**
   * Returns whether code has already been used or not.
   *
   * @return bool
   *   True is code already used otherwise false.
   */
  public function isAlreadyAccepted() {
    return $this->alreadyAccepted;
  }

  /**
   * Store validated code to prevent replay attack.
   *
   * @param string $code
   *   The validated code.
   */
  protected function storeAcceptedCode($code) {
    $code = preg_replace('/\s+/', '', $code);
    $hash = Crypt::hashBase64(Settings::getHashSalt() . $code);

    // Store the hash made using the code in users_data.
    $store_data = ['tfa_accepted_code_' . $hash => \Drupal::time()->getRequestTime()];
    $this->setUserData('tfa', $store_data, $this->uid);
  }

  /**
   * Whether code has already been used.
   *
   * @param string $code
   *   The code to be checked.
   *
   * @return bool
   *   TRUE if already used otherwise FALSE
   */
  protected function alreadyAcceptedCode($code) {
    $hash = Crypt::hashBase64(Settings::getHashSalt() . $code);
    // Check if the code has already been used or not.
    $key    = 'tfa_accepted_code_' . $hash;
    $result = $this->getUserData('tfa', $key, $this->uid);
    if (!empty($result)) {
      $this->alreadyAccepted = TRUE;
      return TRUE;
    }
    return FALSE;
  }

}
