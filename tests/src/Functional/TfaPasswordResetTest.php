<?php

namespace Drupal\Tests\tfa\Functional;

use Drupal\Core\Test\AssertMailTrait;
use Drupal\user\Entity\User;

/**
 * Tests for the tfa login process.
 *
 * @group Tfa
 */
class TfaPasswordResetTest extends TfaTestBase {

  use AssertMailTrait {
    getMails as drupalGetMails;
  }

  /**
   * User doing the TFA Validation.
   *
   * @var \Drupal\user\Entity\User
   */
  protected $webUser;

  /**
   * Administrator to handle configurations.
   *
   * @var \Drupal\user\Entity\User
   */
  protected $adminUser;

  /**
   * Super administrator to edit other users TFA.
   *
   * @var \Drupal\user\Entity\User
   */
  protected $superAdmin;

  /**
   * {@inheritdoc}
   */
  public function setUp(): void {
    parent::setUp();
    // Enable page caching.
    $config = $this->config('system.performance');
    $config->set('cache.page.max_age', 3600);
    $config->save();

    $this->webUser = $this->drupalCreateUser(['setup own tfa']);
    $this->adminUser = $this->drupalCreateUser(['admin tfa settings']);
    $this->superAdmin = User::load(1);
    $this->canEnableValidationPlugin('tfa_test_plugins_validation');

  }

  /**
   * Tests the tfa one time login process.
   */
  public function testTfaOneTimeLogin() {
    $assert_session = $this->assertSession();

    // Enable TFA for the webUser role only.
    $this->drupalLogin($this->adminUser);
    $web_user_roles = $this->webUser->getRoles(TRUE);
    $edit = [
      'tfa_required_roles[' . $web_user_roles[0] . ']' => TRUE,
      'tfa_required_roles[authenticated]' => TRUE,
    ];
    $this->drupalGet('admin/config/people/tfa');
    $this->submitForm($edit, 'Save configuration');
    $assert_session->statusCodeEquals(200);
    $assert_session->pageTextContains('The configuration options have been saved.');

    // Check that tfa is presented via a normal login.
    $this->drupalLogout();
    $edit = [
      'name' => $this->webUser->getAccountName(),
      'pass' => $this->webUser->passRaw,
    ];
    $this->drupalGet('user/login');
    $this->submitForm($edit, 'Log in');
    $assert_session->statusCodeEquals(200);
    $assert_session->addressMatches('/\/tfa\/' . $this->webUser->id() . '/');
    $this->drupalLogout();

    // Check that tfa is presented via one time password reset login.
    // Reset the password by username via the password reset page.
    // login via the one time login URL.
    $this->resetPassword($this->webUser);
    $assert_session->statusCodeEquals(200);
    // And check if the TFA and pass-reset-token are presented.
    $this->isTfaPasswordResetUrl($this->webUser);

    // Check that the super admin user can bypass TFA
    // when resetting the password.
    $this->drupalLogout();
    // Login via the one time login URL.
    $this->resetPassword($this->superAdmin);
    // Change the password.
    $password = \Drupal::service('password_generator')->generate();
    $edit = ['pass[pass1]' => $password, 'pass[pass2]' => $password];
    $this->submitForm($edit, 'Save');
    $assert_session->pageTextContains('The changes have been saved.');

  }

  /**
   * Retrieves password reset email and extracts the login link.
   */
  public function getResetUrl() {
    // Assume the most recent email.
    $_emails = $this->drupalGetMails();
    $email = end($_emails);
    $urls = [];
    preg_match('#.+user/reset/.+#', $email['body'], $urls);
    $path = parse_url($urls[0], PHP_URL_PATH);
    $reset_path = substr($path, strpos($path, 'user/reset/'));

    return $reset_path;
  }

  /**
   * Reset password login process.
   *
   * @param \Drupal\user\Entity\User $user
   *   The user who need to reset the password.
   */
  public function resetPassword(User $user) {
    $this->drupalGet('user/password');
    $edit = ['name' => $user->getAccountName()];
    $this->submitForm($edit, 'Submit');
    // Get the one time reset URL form the email.
    $resetURL = $this->getResetURL() . '/login';
    // Login via one time login URL
    // and check if the TFA presented.
    $this->drupalGet($resetURL);
  }

  /**
   * Check if current path is a valid TFA password reset URL.
   *
   * @param \Drupal\user\Entity\User $user
   *   The user who need to reset the password.
   */
  public function isTfaPasswordResetUrl(User $user) {
    $current_url = $this->getUrl();
    $match = preg_match('/\/tfa\/' . $user->id() . '\/.+?pass-reset-token=.+/', $current_url) ? TRUE : FALSE;
    $this->assertTrue($match, 'It is not a valid tfa path or pass-reset-token is missing in the path.');
  }

}
