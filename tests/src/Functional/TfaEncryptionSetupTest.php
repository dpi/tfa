<?php

declare(strict_types=1);

namespace Drupal\Tests\tfa\Functional;

use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Url;
use Drupal\tfa_test_encryption\Plugin\EncryptionMethod\FailingEncryption;

/**
 * Tests encryption on user TFA setup.
 *
 * @group tfa
 */
final class TfaEncryptionSetupTest extends TfaTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'tfa',
    'encrypt',
    'encrypt_test',
    'key',
    'tfa_test_encryption',
    'tfa_test_plugins',
  ];

  /**
   * Tests handling encryption failure on setup.
   *
   * @param string $encryptionPluginId
   *   Plugin ID of a plugin implementing
   *   \Drupal\encrypt\EncryptionMethodInterface.
   * @param string $expectMessageAfterSetup
   *   Message expected after attempting TFA setup.
   *
   * @dataProvider providerEncryptionOnSetup
   */
  public function testEncryptionOnSetup(string $encryptionPluginId, string $expectMessageAfterSetup): void {
    // Set up the basics programmatically. Speeds things up, and we're not
    // concerned about configuration UI.
    $this->encryptionProfile
      ->set('encryption_method', $encryptionPluginId)
      ->save();

    $validationPluginId = 'tfa_test_plugins_validation';
    $this->config('tfa.settings')
      ->set('enabled', TRUE)
      ->set('required_roles', [
        AccountInterface::AUTHENTICATED_ROLE => AccountInterface::AUTHENTICATED_ROLE,
      ])
      ->set('login_plugins', [])
      ->set('login_plugin_settings', [])
      ->set('default_validation_plugin', $validationPluginId)
      ->set('allowed_validation_plugins', [$validationPluginId => $validationPluginId])
      ->set('validation_plugin_settings', [])
      ->set('encryption', $this->encryptionProfile->id())
      ->save();

    $user = $this->createUser([
      'setup own tfa',
    ]);

    $this->drupalLogin($user);
    $this->getSession()->getPage()->pressButton('Next');
    $this->drupalGet(Url::fromRoute('tfa.overview', ['user' => $user->id()]));
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->responseContains('<h1>TFA</h1>');
    $this->assertSession()->pageTextContains('Number of times validation skipped: 0 of 3');

    $this->drupalGet(Url::fromRoute('tfa.validation.setup', [
      'user' => $user->id(),
      'method' => $validationPluginId,
    ]));
    $this->assertSession()->statusCodeEquals(200);
    $this->submitForm(['current_pass' => $user->passRaw], 'Confirm');
    $this->submitForm(['expected_field' => $this->randomMachineName()], 'Verify and save');
    $this->assertSession()->pageTextContains($expectMessageAfterSetup);
    $this->assertSession()->pageTextContains('Number of times validation skipped: 0 of 3');
  }

  /**
   * Data provider.
   *
   * @return array[]
   *   Data for testing.
   */
  public function providerEncryptionOnSetup(): array {
    return [
      'failure' => [
        FailingEncryption::PLUGIN_ID,
        'There was an error during TFA setup. Your settings have not been saved.',
      ],
      'success' => [
        'test_encryption_method',
        'TFA setup complete.',
      ],
    ];
  }

}
