<?php

declare(strict_types=1);

namespace Drupal\tfa\Event;

use Drupal\user\UserInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Determine whether to enforce TFA for a user.
 *
 * By default, TFA is enforced when:
 * - TFA is enabled globally
 * - User has permission to use TFA
 * - TFA is set up for a user.
 *
 * TFA is not enforced for a user if they are not configured to use TFA, or the
 * user has not started or finished setting up TFA.
 *
 * @internal
 *   There is no extensibility promise for this class.
 */
final class TfaUserHasTfaEvent extends Event {

  /**
   * A user entity.
   *
   * @var \Drupal\user\UserInterface
   */
  private $user;

  /**
   * Whether TFA is enforced for this user.
   *
   * @var bool
   */
  private $enforce = FALSE;

  /**
   * Constructs a new TfaUserHasTfaEvent.
   *
   * @internal
   *   Initialisation of this class may only happen via TFA. Internals of this
   *   event may change at any time.
   */
  protected function __construct(UserInterface $user) {
    $this->user = $user;
  }

  /**
   * Creates a new TfaUserHasTfaEvent.
   *
   * @return static
   *   Returns a new TfaUserHasTfaEvent for a user.
   *
   * @internal
   *   This factory may change at any time.
   */
  public static function create(UserInterface $user) {
    return new static($user);
  }

  /**
   * Gets the user.
   *
   * @return \Drupal\user\UserInterface
   *   The user.
   */
  public function getUser(): UserInterface {
    return $this->user;
  }

  /**
   * Determine whether TFA is enforced for this user.
   *
   * @return bool
   *   Whether TFA is enforced for this user.
   */
  public function isEnforcingTfa(): bool {
    return $this->enforce;
  }

  /**
   * Whether to enforce TFA for this user.
   *
   * @return $this
   *   Returns this object for chaining.
   */
  public function enforceTfa() {
    $this->enforce = TRUE;
    return $this;
  }

  /**
   * Whether to un-enforce TFA for this user.
   *
   * @return $this
   *   Returns this object for chaining.
   */
  public function unEnforceTfa() {
    $this->enforce = FALSE;
    return $this;
  }

}
