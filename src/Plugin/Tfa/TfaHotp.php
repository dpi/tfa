<?php

namespace Drupal\tfa\Plugin\Tfa;

use chillerlan\QRCode\QRCode;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Link;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Url;
use Drupal\encrypt\EncryptionProfileManagerInterface;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\encrypt\Exception\EncryptException;
use Drupal\tfa\Plugin\TfaSetupInterface;
use Drupal\tfa\Plugin\TfaValidationInterface;
use Drupal\tfa\TfaBasePlugin;
use Drupal\user\UserDataInterface;
use Drupal\user\UserStorageInterface;
use Otp\GoogleAuthenticator;
use Otp\Otp;
use ParagonIE\ConstantTime\Encoding;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * HOTP validation class for performing HOTP validation.
 *
 * @Tfa(
 *   id = "tfa_hotp",
 *   label = @Translation("TFA HMAC-based one-time password (HOTP)"),
 *   description = @Translation("TFA HOTP Validation Plugin"),
 *   helpLinks = {
 *    "Google Authenticator (Android/iOS)" = "https://googleauthenticator.net",
 *    "Microsoft Authenticator (Android/iOS)" = "https://www.microsoft.com/en-us/security/mobile-authenticator-app",
 *    "FreeOTP (Android/iOS)" = "https://freeotp.github.io",
 *   },
 *   setupMessages = {
 *    "saved" = @Translation("Application code verified."),
 *    "skipped" = @Translation("Application codes not enabled."),
 *   }
 * )
 */
class TfaHotp extends TfaBasePlugin implements TfaValidationInterface, TfaSetupInterface, ContainerFactoryPluginInterface {

  /**
   * Object containing the external validation library.
   *
   * @var object
   */
  public $auth;

  /**
   * The counter window in which the validation should be done.
   *
   * @var int
   */
  protected $counterWindow;

  /**
   * Whether or not the prefix should use the site name.
   *
   * @var bool
   */
  protected $siteNamePrefix;

  /**
   * Name prefix.
   *
   * @var string
   */
  protected $namePrefix;

  /**
   * Configurable name of the issuer.
   *
   * @var string
   */
  protected $issuer;

  /**
   * The Datetime service.
   *
   * @var \Drupal\Component\Datetime\TimeInterface
   */
  protected $time;

  /**
   * The user storage.
   *
   * @var \Drupal\user\UserStorageInterface
   */
  protected $userStorage;

  /**
   * Un-encrypted seed.
   *
   * @var string
   */
  protected $seed;

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
   * @param \Drupal\user\UserDataInterface $user_data
   *   User data object to store user specific information.
   * @param \Drupal\encrypt\EncryptionProfileManagerInterface $encryption_profile_manager
   *   Encryption profile manager.
   * @param \Drupal\encrypt\EncryptServiceInterface $encrypt_service
   *   Encryption service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The configuration factory.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The datetime service.
   * @param \Drupal\user\UserStorageInterface $user_storage
   *   The user storage.
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, UserDataInterface $user_data, EncryptionProfileManagerInterface $encryption_profile_manager, EncryptServiceInterface $encrypt_service, ConfigFactoryInterface $config_factory, TimeInterface $time, UserStorageInterface $user_storage) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);

    $this->auth = new \StdClass();
    $this->auth->otp = new Otp();
    $this->auth->ga = new GoogleAuthenticator();
    $plugin_settings = $config_factory->get('tfa.settings')->get('validation_plugin_settings');
    $settings = $plugin_settings[$plugin_id] ?? [];
    $settings = array_replace([
      'counter_window' => 10,
      'site_name_prefix' => TRUE,
      'name_prefix' => 'TFA',
      'issuer' => 'Drupal',
    ], $settings);

    $this->userData = $user_data;
    $this->counterWindow = $settings['counter_window'];
    $this->siteNamePrefix = $settings['site_name_prefix'];
    $this->namePrefix = $settings['name_prefix'];
    $this->issuer = $settings['issuer'];
    $this->time = $time;
    $this->userStorage = $user_storage;

    $this->encryptionProfile = $encryption_profile_manager->getEncryptionProfile($config_factory->get('tfa.settings')->get('encryption'));
    $this->encryptService = $encrypt_service;

    // Generate seed.
    $this->setSeed($this->createSeed());
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('user.data'),
      $container->get('encrypt.encryption_profile.manager'),
      $container->get('encryption'),
      $container->get('config.factory'),
      $container->get('datetime.time'),
      $container->get('entity_type.manager')->getStorage('user')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function ready() {
    return ($this->getSeed() !== FALSE);
  }

  /**
   * {@inheritdoc}
   */
  public function getForm(array $form, FormStateInterface $form_state) {
    $message = $this->t('Verification code is application generated and @length digits long.', ['@length' => $this->codeLength]);
    if ($this->getUserData('tfa', 'tfa_recovery_code', $this->uid)) {
      $message .= '<br/>' . $this->t("Can't access your account? Use one of your recovery codes.");
    }
    $form['code'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Application verification code'),
      '#description' => $message,
      '#required'  => TRUE,
      '#attributes' => [
        'autocomplete' => 'off',
        'autofocus' => 'autofocus',
      ],
    ];

    $form['actions']['#type'] = 'actions';
    $form['actions']['login'] = [
      '#type' => 'submit',
      '#button_type' => 'primary',
      '#value' => $this->t('Verify'),
    ];

    return $form;
  }

  /**
   * The configuration form for this validation plugin.
   *
   * @return array
   *   Form array specific for this validation plugin.
   */
  public function buildConfigurationForm() {
    $settings_form['counter_window'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Counter Window'),
      '#default_value' => ($this->counterWindow) ?: 5,
      '#description' => $this->t('How far ahead from current counter should we check the code.'),
      '#size' => 2,
      '#required' => TRUE,
    ];

    $settings_form['site_name_prefix'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Use site name as OTP QR code name prefix.'),
      '#default_value' => $this->siteNamePrefix,
      '#description' => $this->t('If checked, the site name will be used instead of a static string. This can be useful for multi-site installations.'),
    ];

    $settings_form['name_prefix'] = [
      '#type' => 'textfield',
      '#title' => $this->t('OTP QR Code Prefix'),
      '#default_value' => $this->namePrefix ?? 'tfa',
      '#description' => $this->t('Prefix for OTP QR code names. Suffix is account username.'),
      '#size' => 15,
      '#states' => [
        'visible' => [':input[name="validation_plugin_settings[' . $this->pluginId . '][site_name_prefix]"]' => ['checked' => FALSE]],
      ],
    ];

    $settings_form['issuer'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Issuer'),
      '#default_value' => $this->issuer,
      '#description' => $this->t('The provider or service this account is associated with.'),
      '#size' => 15,
      '#required' => TRUE,
    ];

    return $settings_form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array $form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    if (!$this->validate($values['code'])) {
      $this->errorMessages['code'] = $this->t('Invalid application code. Please try again.');
      if ($this->alreadyAccepted) {
        $form_state->clearErrors();
        $this->errorMessages['code'] = $this->t('Invalid code, it was recently used for a login. Please try a new code.');
      }
      return FALSE;
    }
    else {
      // Store accepted code to prevent replay attacks.
      $this->storeAcceptedCode($values['code']);
      return TRUE;
    }
  }

  /**
   * Simple validate for web services.
   *
   * @param int $code
   *   OTP Code.
   *
   * @return bool
   *   True if validation was successful otherwise false.
   */
  public function validateRequest($code) {
    if ($this->validate($code)) {
      $this->storeAcceptedCode($code);
      return TRUE;
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  protected function validate($code) {
    // Strip whitespace.
    $code = preg_replace('/\s+/', '', $code);
    if ($this->alreadyAcceptedCode($code)) {
      $this->isValid = FALSE;
    }
    else {
      // Get OTP seed.
      $seed = $this->getSeed();
      $counter = $this->getHotpCounter();
      $this->isValid = ($seed && ($counter = $this->auth->otp->checkHotpResync(Encoding::base32DecodeUpper($seed), $counter, $code, $this->counterWindow)));
      $this->setUserData('tfa', [$this->pluginId . '_counter' => ++$counter], $this->uid);
    }
    return $this->isValid;
  }

  /**
   * Get seed for this account.
   *
   * @return string
   *   Decrypted account OTP seed or FALSE if none exists.
   */
  protected function getSeed() {
    // Lookup seed for account and decrypt.
    $result = $this->getUserData('tfa', $this->pluginId . '_seed', $this->uid);

    if (!empty($result)) {
      $encrypted = base64_decode($result['seed']);
      $seed = $this->encryptService->decrypt($encrypted, $this->encryptionProfile);
      if (!empty($seed)) {
        return $seed;
      }
    }
    return FALSE;
  }

  /**
   * Save seed for account.
   *
   * @param string $seed
   *   Un-encrypted seed.
   *
   * @throws \Drupal\encrypt\Exception\EncryptException
   *   Can throw an EncryptException.
   */
  public function storeSeed($seed) {
    // Encrypt seed for storage.
    $encrypted = $this->encryptService->encrypt($seed, $this->encryptionProfile);

    // Until EncryptServiceInterface::encrypt enforces a non-empty string,
    // validate return value is a non-empty string. \base64_encode() below must
    // also only receive a string.
    if (!is_string($encrypted) || strlen($encrypted) === 0) {
      throw new EncryptException('Empty encryption value received from encryption service.');
    }

    $record = [
      $this->pluginId . '_seed' => [
        'seed' => base64_encode($encrypted),
        'created' => $this->time->getRequestTime(),
      ],
    ];

    $this->setUserData('tfa', $record, $this->uid);
  }

  /**
   * Delete the seed of the current validated user.
   */
  protected function deleteSeed() {
    $this->deleteUserData('tfa', $this->pluginId . '_seed', $this->uid);
  }

  /**
   * Get the HOTP counter.
   *
   * @return int
   *   The current value of the HOTP counter, or 1 if no value was found.
   */
  public function getHotpCounter() {
    return ($this->getUserData('tfa', $this->pluginId . '_counter', $this->uid)) ?: 1;
  }

  /* ================================== SETUP ================================== */

  /**
   * {@inheritdoc}
   */
  public function getSetupForm(array $form, FormStateInterface $form_state) {
    $help_links = $this->getHelpLinks();

    $items = [];
    foreach ($help_links as $item => $link) {
      $items[] = Link::fromTextAndUrl($item, Url::fromUri($link, ['attributes' => ['target' => '_blank']]));
    }

    $form['apps'] = [
      '#theme' => 'item_list',
      '#items' => $items,
      '#title' => $this->t('Install authentication code application on your mobile or desktop device:'),
    ];
    $form['info'] = [
      '#type' => 'html_tag',
      '#tag' => 'p',
      '#value' => $this->t('The two-factor authentication application will be used during this setup and for generating codes during regular authentication. If the application supports it, scan the QR code below to get the setup code otherwise you can manually enter the text code.'),
    ];
    $form['seed'] = [
      '#type' => 'textfield',
      '#value' => $this->seed,
      '#disabled' => TRUE,
      '#description' => $this->t('Enter this code into your two-factor authentication app or scan the QR code below.'),
    ];

    // QR image of seed.
    $form['qr_image'] = [
      '#prefix' => '<div class="tfa-qr-code"',
      '#theme' => 'image',
      '#uri' => $this->getQrCodeUri(),
      '#alt' => $this->t('QR code for TFA setup'),
      '#suffix' => '</div>',
    ];

    // QR code css giving it a fixed width.
    $form['page']['#attached']['html_head'][] = [
      [
        '#tag' => 'style',
        '#value' => ".tfa-qr-code { width:200px }",
      ],
      'qrcode-css',
    ];

    // Include code entry form.
    $form = $this->getForm($form, $form_state);
    $form['actions']['login']['#value'] = $this->t('Verify and save');
    // Alter code description.
    $form['code']['#description'] = $this->t('A verification code will be generated after you scan the above QR code or manually enter the setup code. The verification code is six digits long.');
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateSetupForm(array $form, FormStateInterface $form_state) {
    if (!$this->validateSetup($form_state->getValue('code'))) {
      $this->errorMessages['code'] = $this->t('Invalid application code. Please try again.');
      return FALSE;
    }
    $this->storeAcceptedCode($form_state->getValue('code'));
    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  protected function validateSetup($code) {
    // The counter is set as 1 because that is the initial value.
    // This ensures that things work even if we reset the application.
    $code = preg_replace('/\s+/', '', $code);
    $counter = $this->auth->otp->checkHotpResync(Encoding::base32DecodeUpper($this->seed), 1, $code, $this->counterWindow);
    $this->setUserData('tfa', [$this->pluginId . '_counter' => ++$counter], $this->uid);
    return ((bool) $counter);
  }

  /**
   * {@inheritdoc}
   */
  public function submitSetupForm(array $form, FormStateInterface $form_state) {
    // Write seed for user.
    try {
      $this->storeSeed($this->seed);
      return TRUE;
    }
    catch (EncryptException $e) {
    }
    return FALSE;
  }

  /**
   * Get a base64 qrcode image uri of seed.
   *
   * @return string
   *   QR-code uri.
   */
  protected function getQrCodeUri() {
    return (new QRCode)->render('otpauth://hotp/' . $this->accountName() . '?secret=' . $this->seed . '&counter=1&issuer=' . urlencode($this->issuer));
  }

  /**
   * Create OTP seed for account.
   *
   * @return string
   *   Un-encrypted seed.
   */
  protected function createSeed() {
    return $this->auth->ga->generateRandom();
  }

  /**
   * Setter for OTP secret key.
   *
   * @param string $seed
   *   The OTP secret key.
   */
  public function setSeed($seed) {
    $this->seed = $seed;
  }

  /**
   * Get account name for QR image.
   *
   * @return string
   *   URL encoded string.
   */
  protected function accountName() {
    /** @var \Drupal\user\Entity\User $account */
    $account = $this->userStorage->load($this->configuration['uid']);
    $prefix = $this->siteNamePrefix ? preg_replace('@[^a-z0-9-]+@', '-', strtolower(\Drupal::config('system.site')->get('name'))) : $this->namePrefix;
    return urlencode((!empty($prefix) ? $prefix . '-' : '') . $account->getAccountName());
  }

  /**
   * {@inheritdoc}
   */
  public function getOverview(array $params) {
    $plugin_text = $this->t('Validation Plugin: @plugin',
      [
        '@plugin' => str_replace(' Setup', '', $this->getLabel()),
      ]
    );
    $output = [
      'heading' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('TFA application'),
      ],
      'validation_plugin' => [
        '#type' => 'markup',
        '#markup' => '<p>' . $plugin_text . '</p>',
      ],
      'description' => [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => $this->t('Generate verification codes from a mobile or desktop application.'),
      ],
      'link' => [
        '#theme' => 'links',
        '#links' => [
          'admin' => [
            'title' => !$params['enabled'] ? $this->t('Set up application') : $this->t('Reset application'),
            'url' => Url::fromRoute('tfa.validation.setup', [
              'user' => $params['account']->id(),
              'method' => $params['plugin_id'],
            ]),
          ],
        ],
      ],
    ];
    return $output;
  }

}
