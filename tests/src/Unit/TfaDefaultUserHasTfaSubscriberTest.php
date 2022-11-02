<?php

declare(strict_types=1);

namespace Drupal\Tests\tfa\Unit;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Tests\UnitTestCase;
use Drupal\tfa\Event\TfaUserHasTfaEvent;
use Drupal\tfa\EventSubscriber\TfaDefaultUserHasTfaSubscriber;
use Drupal\tfa\TfaPluginManager;
use Drupal\user\UserDataInterface;
use Drupal\user\UserInterface;

/**
 * Tests default user-has-TFA behavior.
 *
 * @group tfa
 * @coversDefaultClass \Drupal\tfa\EventSubscriber\TfaDefaultUserHasTfaSubscriber
 */
final class TfaDefaultUserHasTfaSubscriberTest extends UnitTestCase {

  /**
   * Tests default user-has-TFA behavior.
   *
   * @param bool $expectEnforceTfa
   *   Whether to expect event will require TFA.
   * @param array|null $settingsMap
   *   Settings map, or NULL to expect settings are fetched once.
   * @param array|null $userDataUserSettings
   *   User data, or NULL to expect user data will never be fetched.
   * @param array $userRoles
   *   Roles to assign to test user.
   *
   * @covers ::listenerUserHasTfaSubscriber
   * @dataProvider listenerProvider
   */
  public function testListener(bool $expectEnforceTfa, ?array $settingsMap, ?array $userDataUserSettings, array $userRoles): void {
    $settings = $this->createMock(ImmutableConfig::class);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->expects($this->any())
      ->method('get')
      ->with('tfa.settings')
      ->willReturn($settings);

    if ($settingsMap !== NULL) {
      $settings
        ->expects($this->atLeastOnce())
        ->method('get')
        ->willReturnMap($settingsMap);
    }
    else {
      $settings->expects($this->once())->method('get');
    }

    $userData = $this->createMock(UserDataInterface::class);
    if ($userDataUserSettings !== NULL) {
      $userData
        ->expects($this->once())
        ->method('get')
        ->with('tfa', '1337', 'tfa_user_settings')
        ->willReturn($userDataUserSettings);
    }
    else {
      $userData->expects($this->never())->method('get');
    }

    $tfaPluginManager = $this->createMock(TfaPluginManager::class);
    $tfaPluginManager->expects($this->any())
      ->method('hasDefinition')
      ->willReturnMap([
        ['my_validation_plugin', TRUE],
        ['some_invalid_validation_plugin', FALSE],
      ]);
    $subscriber = new TfaDefaultUserHasTfaSubscriber($configFactory, $userData, $tfaPluginManager);
    $user = $this->createMock(UserInterface::class);
    $user
      ->expects($this->any())
      ->method('id')
      ->willReturn('1337');
    $user
      ->expects($this->any())
      ->method('getRoles')
      ->willReturn($userRoles);
    $event = TfaUserHasTfaEvent::create($user);
    $subscriber->listenerUserHasTfaSubscriber($event);
    $this->assertEquals($expectEnforceTfa, $event->isEnforcingTfa());
  }

  /**
   * Data provider.
   *
   * @return \Generator
   *   Data for testing.
   */
  public function listenerProvider(): \Generator {
    yield 'when there is no settings' => [
      FALSE,
      'settingsMap' => NULL,
      'userDataUserSettings' => NULL,
      'userRoles' => [],
    ];

    yield 'when isTfaEnabled is false' => [
      FALSE,
      'settingsMap' => [
        ['enabled', FALSE],
      ],
      'userDataUserSettings' => NULL,
      'userRoles' => [],
    ];

    yield 'default plugin is invalid or does not exist' => [
      FALSE,
      'settingsMap' => [
        ['enabled', TRUE],
        ['default_validation_plugin', 'some_invalid_validation_plugin'],
      ],
      'userDataUserSettings' => NULL,
      'userRoles' => [],
    ];

    yield 'user data requires tfa' => [
      TRUE,
      'settingsMap' => [
        ['enabled', TRUE],
        ['default_validation_plugin', 'my_validation_plugin'],
      ],
      'userDataUserSettings' => [
        'status' => TRUE,
        'data' => [
          'plugins' => ['tfa_totp'],
        ],
      ],
      'userRoles' => [],
    ];

    yield 'user roles does not require tfa' => [
      FALSE,
      'settingsMap' => [
        ['enabled', TRUE],
        ['default_validation_plugin', 'my_validation_plugin'],
        [
          'required_roles', ['test_role' => 'test_role'],
        ],
      ],
      'userDataUserSettings' => [],
      'userRoles' => [],
    ];

    yield 'user roles require tfa' => [
      TRUE,
      'settingsMap' => [
        ['enabled', TRUE],
        ['default_validation_plugin', 'my_validation_plugin'],
        [
          'required_roles', ['test_role' => 'test_role'],
        ],
      ],
      'userDataUserSettings' => [],
      'userRoles' => ['test_role'],
    ];
  }

}
