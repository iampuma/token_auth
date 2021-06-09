<?php

namespace Drupal\token_auth;

use Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException;
use Drupal\Component\Plugin\Exception\PluginNotFoundException;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountProxy;
use Drupal\user\UserInterface;
use Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class AuthTokenMiddleware implements HttpKernelInterface
{
  public const QUERY_PARAM_AUTH_TOKEN = 'authtoken';
  public const FIELD_AUTH_TOKEN = 'field_auth_token';

  private HttpKernelInterface $httpKernel;
  private EntityTypeManagerInterface $entityTypeManager;
  private AccountProxy $user;

  /**
   * AuthTokenMiddleware constructor.
   *
   * @param HttpKernelInterface $http_kernel
   * @param EntityTypeManagerInterface $entityTypeManager
   * @param AccountProxy $user
   */
  public function __construct(
    HttpKernelInterface $http_kernel,
    EntityTypeManagerInterface $entityTypeManager,
    AccountProxy $user
  )
  {
    $this->httpKernel = $http_kernel;
    $this->entityTypeManager = $entityTypeManager;
    $this->user = $user;
  }

  /**
   * @param Request $request
   * @param int $type
   * @param bool $catch
   * @return Response
   * @throws Exception
   */
  public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = TRUE): Response
  {
    $authToken = $request->get(self::QUERY_PARAM_AUTH_TOKEN);
    if (!empty($authToken) && $account = $this->loadUserByAuthToken($authToken)) {
      $this->user->setAccount($account);
    }
    return $this->httpKernel->handle($request, $type, $catch);
  }

  /**
   * @param string $authToken
   * @return UserInterface|null
   * @throws InvalidPluginDefinitionException
   * @throws PluginNotFoundException
   */
  private function loadUserByAuthToken(string $authToken): ?UserInterface
  {
    $user = null;

    $query = $this->entityTypeManager->getStorage('user')->getQuery();
    $users = $query->condition('status', 1)
      ->condition(self::FIELD_AUTH_TOKEN, $authToken)
      ->execute();

    if ($uid = reset($users)) {
      /** @var UserInterface $user */
      $user = $this->entityTypeManager->getStorage('user')->load($uid);
    }

    return $user;
  }

  /**
   * Returns a random generated authentication token string.
   */
  public function generateAuthToken(): string
  {
    $authToken = '';

    try {
      $authToken = md5(random_bytes(10));
    } catch (Exception $e) {
      \Drupal::logger('token_auth')->critical(t('Error generating auth token: @message', [
        '@message' => $e->getMessage()
      ]));
    }

    return $authToken;
  }
}
