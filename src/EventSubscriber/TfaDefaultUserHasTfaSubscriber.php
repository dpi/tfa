<?php

declare(strict_types=1);

namespace Drupal\tfa\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\tfa\Event\TfaUserHasTfaEvent;
use Drupal\tfa\TfaPluginManager;
use Drupal\tfa\TfaUserDataTrait;
use Drupal\user\UserDataInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Default behavior for determining if TFA is enforced for users.
 *
 * @internal
 *   There is no extensibility promise for this class. To override this
 *   functionality, you may subscribe to events at a higher priority, then
 *   set $event->stopPropagation(). Or you may remove or replace this class
 *   entirely in service registration by implementing a ServiceProvider.
 */
final class TfaDefaultUserHasTfaSubscriber implements EventSubscriberInterface {

  use TfaUserDataTrait;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  private $configFactory;

  /**
   * TFA plugin manager.
   *
   * @var \Drupal\tfa\TfaPluginManager
   */
  private $tfaPluginManager;

  /**
   * Constructs a new TfaDefaultUserHasTfaSubscriber.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\user\UserDataInterface $userData
   *   User data.
   * @param \Drupal\tfa\TfaPluginManager $tfaPluginManager
   *   TFA plugin manager.
   */
  final public function __construct(ConfigFactoryInterface $configFactory, UserDataInterface $userData, TfaPluginManager $tfaPluginManager) {
    $this->configFactory = $configFactory;
    $this->userData = $userData;
    $this->tfaPluginManager = $tfaPluginManager;
  }

  /**
   * Default behavior for determining if TFA is enforced for users.
   */
  public function listenerUserHasTfaSubscriber(TfaUserHasTfaEvent $event): void {
    // Global TFA settings take precedence.
    if (!$this->isTfaEnabled()) {
      // Leave as current value, quit.
      return;
    }

    if (!$this->hasValidDefaultValidationPlugin()) {
      // Leave as current value, quit.
      return;
    }

    $userTfaData = $this->tfaGetTfaData($event->getUser()->id());
    if (!empty($userTfaData['status']) && !empty($userTfaData['data']['plugins'])) {
      $event->enforceTfa();
      return;
    }

    // TFA is not necessary if the user doesn't have one of the required roles.
    if (count(array_intersect($this->getRequiredRoles(), $event->getUser()->getRoles())) > 0) {
      $event->enforceTfa();
      // Keep return in case more is added below. We want to exit before
      // anything new after this.
      return;
    }
  }

  /**
   * Determine if TFA is enabled globally.
   *
   * @return bool
   *   Whether TFA is enabled globally.
   */
  private function isTfaEnabled(): bool {
    return $this->configFactory->get('tfa.settings')->get('enabled') ?? FALSE;
  }

  /**
   * Determines if default validation plugin is a valid plugin.
   *
   * @return bool
   *   Whether default validation plugin is a valid plugin.
   */
  private function hasValidDefaultValidationPlugin(): bool {
    $pluginId = $this->configFactory->get('tfa.settings')->get('default_validation_plugin') ?? '';
    return $this->tfaPluginManager->hasDefinition($pluginId);
  }

  /**
   * Get roles requiring TFA.
   *
   * @return string[]
   *   The roles requiring TFA.
   */
  private function getRequiredRoles(): array {
    return array_filter($this->configFactory->get('tfa.settings')->get('required_roles') ?? []);
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    return [
      TfaUserHasTfaEvent::class => [
        // Explicitly indicate this is priority=zero so consumers know we won't
        // change it in the future.
        ['listenerUserHasTfaSubscriber', 0],
      ],
    ];
  }

}
