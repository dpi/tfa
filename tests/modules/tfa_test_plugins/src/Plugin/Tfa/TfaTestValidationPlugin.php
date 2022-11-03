<?php

namespace Drupal\tfa_test_plugins\Plugin\Tfa;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\encrypt\EncryptionProfileManagerInterface;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\encrypt\Exception\EncryptException;
use Drupal\tfa\Plugin\TfaSetupInterface;
use Drupal\tfa\Plugin\TfaValidationInterface;
use Drupal\tfa\TfaBasePlugin;
use Drupal\user\UserDataInterface;
use Drupal\user\UserStorageInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * TFA Test Validation Plugin.
 *
 * @package Drupal\tfa_test_plugins
 *
 * @Tfa(
 *   id = "tfa_test_plugins_validation",
 *   label = @Translation("TFA Test Validation Plugin"),
 *   description = @Translation("TFA Test Validation Plugin"),
 *   helpLinks = {},
 *   setupMessages = {}
 * )
 */
class TfaTestValidationPlugin extends TfaBasePlugin implements TfaValidationInterface, TfaSetupInterface, ContainerFactoryPluginInterface {
  use StringTranslationTrait;

  /**
   * The user storage.
   *
   * @var \Drupal\user\UserStorageInterface
   */
  protected $userStorage;

  /**
   * Encryption profile.
   *
   * @var \Drupal\encrypt\EncryptionProfileManagerInterface
   */
  protected $encryptionProfile;

  /**
   * Encryption service.
   *
   * @var \Drupal\encrypt\EncryptService
   */
  protected $encryptService;

  /**
   * Constructs a new Tfa plugin object.
   *
   * @param array $configuration
   *   The plugin configuration.
   * @param string $plugin_id
   *   The plugin id.
   * @param mixed $plugin_definition
   *   The plugin definition.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The configuration factory.
   * @param \Drupal\user\UserDataInterface $user_data
   *   User data object to store user specific information.
   * @param \Drupal\user\UserStorageInterface $user_storage
   *   The user storage.
   * @param \Drupal\encrypt\EncryptServiceInterface $encrypt_service
   *   Encryption service.
   * @param \Drupal\encrypt\EncryptionProfileManagerInterface $encryption_profile_manager
   *   Encryption profile manager.
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, ConfigFactoryInterface $config_factory, UserDataInterface $user_data, UserStorageInterface $user_storage, EncryptServiceInterface $encrypt_service, EncryptionProfileManagerInterface $encryption_profile_manager) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);

    $this->userData = $user_data;
    $this->userStorage = $user_storage;
    $this->encryptionProfile = $encryption_profile_manager->getEncryptionProfile($config_factory->get('tfa.settings')->get('encryption'));
    $this->encryptService = $encrypt_service;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('config.factory'),
      $container->get('user.data'),
      $container->get('entity_type.manager')->getStorage('user'),
      $container->get('encryption'),
      $container->get('encrypt.encryption_profile.manager')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getForm(array $form, FormStateInterface $form_state) {
    $form['actions']['login'] = [
      '#type' => 'submit',
      '#button_type' => 'primary',
      '#value' => $this->t('Next'),
    ];
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array $form, FormStateInterface $form_state) {
    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  public function ready() {
    return TRUE;
  }

  /* ================================== SETUP ================================== */

  /**
   * {@inheritdoc}
   */
  public function getSetupForm(array $form, FormStateInterface $form_state) {
    $form['user']['#markup'] = $this->t('<p>TFA Setup for @name</p>', [
      '@name' => $this->userStorage->load($this->configuration['uid'])->getDisplayName(),
    ]);
    $form['expected_field'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Expected field'),
      '#required' => TRUE,
    ];
    $form['actions']['#type'] = 'actions';
    $form['actions']['login'] = [
      '#type'  => 'submit',
      '#button_type' => 'primary',
      '#value' => $this->t('Verify and save'),
    ];
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateSetupForm(array $form, FormStateInterface $form_state) {
    $expected_value = $form_state->getValue('expected_field');

    if (empty($expected_value)) {
      $form_state->setError($form['expected_field'], $this->t('Missing expected value.'));
      return FALSE;
    }

    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  public function submitSetupForm(array $form, FormStateInterface $form_state) {
    try {
      $encrypted = $this->encryptService->encrypt($form_state->getValue('expected_field'), $this->encryptionProfile);
    }
    catch (EncryptException $e) {
      return FALSE;
    }

    $record = [
      'test_data' => [
        'expected_field' => base64_encode($encrypted),
      ],
    ];
    $this->setUserData($this->pluginDefinition['id'], $record, $this->uid, $this->userData);

    return TRUE;
  }

  /**
   * Get and decode the data expected during setup.
   *
   * @return null|string
   *   The string if found, otherwise NULL;
   *
   * @throws \Drupal\encrypt\Exception\EncryptionMethodCanNotDecryptException
   * @throws \Drupal\encrypt\Exception\EncryptException
   */
  public function getExpectedFieldData() {
    $data = $this->getUserData($this->pluginDefinition['id'], 'test_data', $this->uid, $this->userData);
    if (!empty($data['expected_field'])) {
      return $this->encryptService->decrypt(base64_decode($data['expected_field']), $this->encryptionProfile);
    }

    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function getHelpLinks() {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function getSetupMessages() {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function getOverview(array $params) {
    return [
      'heading' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('TFA application'),
      ],
      'link' => [
        '#theme' => 'links',
        '#links' => [
          'admin' => [
            'title' => !$params['enabled'] ? $this->t('Set up test application') : $this->t('Reset test application'),
            'url' => Url::fromRoute('tfa.validation.setup', [
              'user' => $params['account']->id(),
              'method' => $params['plugin_id'],
            ]),
          ],
        ],
      ],
    ];
  }

}
