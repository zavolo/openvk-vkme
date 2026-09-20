<?php

declare(strict_types=1);

namespace openvk\VKAPI\Handlers;

use Chandler\Database\DatabaseConnection as DB;
use Chandler\Security\Authenticator;
use openvk\VKAPI\ClientRegistry;
use openvk\Web\Models\Entities\{User, APIToken};
use openvk\Web\Models\Repositories\{Users, APITokens};
use lfkeitel\phptotp\{Base32, Totp};

final class Auth extends VKAPIRequestHandler
{
    public function validateAccount(string $login = "", string $sid = ""): object
    {
        $login = trim($login);
        $isEmail = strpos($login, "@") !== false;
        $exists = false;
        if ($login !== "") {
            $chUser = DB::i()->getContext()->table("ChandlerUsers")->where("login", $login)->fetch();
            if ($chUser) {
                $exists = true;
            } else {
                $profile = DB::i()->getContext()->table("profiles")->where("email", $login)->fetch();
                $exists = (bool) $profile;
            }
        }
        if ($exists) {
            return (object) [
                "flow_names" => ["password"],
                "flow_name"  => "need_password",
                "next_step"  => (object) ["verification_method" => "password"],
                "sid"        => "1",
                "is_email"   => $isEmail,
                "is_phone"   => !$isEmail,
                "login"      => $login,
            ];
        }
        return (object) [
            "flow_names" => [],
            "flow_name"  => "need_registration",
            "sid"        => "1",
            "is_email"   => $isEmail,
            "is_phone"   => !$isEmail,
            "login"      => $login,
        ];
    }

    public function getTokenSecure(?string $nonce = null, ?int $api_id = null, mixed $client_id = null): array
    {
        return [
            "token"  => bin2hex(random_bytes(16)),
            "secret" => bin2hex(random_bytes(8)),
        ];
    }

    public function getSessionSecure(
        ?string $login = null,
        ?string $username = null,
        ?string $password = null,
        ?string $digest = null,
        ?int $api_id = null,
        ?string $nonce = null,
        mixed $client_id = null,
        ?string $code = null,
        mixed $scope = null
    ): array {
        $login = !empty($login) ? trim($login) : (!empty($username) ? trim($username) : null);
        $password = !empty($password) ? $password : $digest;

        if (empty($login) || empty($password)) {
            $this->fail(100, "Password and login not passed");
        }

        $chUser = DB::i()->getContext()->table("ChandlerUsers")->where("login", $login)->fetch();
        if (!$chUser) {
            $profile = DB::i()->getContext()->table("profiles")->where("email", $login)->fetch();
            if ($profile && $profile->user) {
                $chUser = DB::i()->getContext()->table("ChandlerUsers")->where("id", $profile->user)->fetch();
            }
        }

        if (!$chUser) {
            $this->fail(28, "Invalid login or password");
        }

        $auth = Authenticator::i();
        if (!$auth->verifyCredentials($chUser->id, $password)) {
            $this->fail(28, "Invalid login or password");
        }

        $uId  = $chUser->related("profiles.user")->fetch()->id;
        $user = (new Users())->get($uId);

        if (!$user) {
            $this->fail(28, "Invalid login or password");
        }

        if (!$user->isActivated() && (OPENVK_ROOT_CONF['openvk']['preferences']['security']['requireEmail'] ?? false) === true) {
            $this->fail(7, "Access denied");
        }

        if ($user->isBanned() || $user->isDeleted()) {
            $this->fail(18, "User was deleted or banned");
        }

        if ($user->is2faEnabled()) {
            if (empty($code) || !($code === (new Totp())->GenerateToken(Base32::decode($user->get2faSecret())) || $user->use2faBackupCode((int) $code))) {
                $this->fail(28, "Invalid 2FA code");
            }
        }

        $rawClientId = !empty($api_id) ? $api_id : $client_id;
        $clientInfo  = ClientRegistry::resolve($rawClientId);
        $platform    = $clientInfo['tag'] ?? null;
        $clientId    = !empty($rawClientId) && is_numeric($rawClientId) ? (int) $rawClientId : ($clientInfo['id'] ?? null);

        if (empty($platform)) {
            $platform = "vk_android";
        }

        $token = (new APITokens())->getStaleByUser($uId, $platform);
        if (is_null($token)) {
            $token = new APIToken();
            $token->setUser($user);
            if (!empty($clientId)) {
                $token->setClientId((int) $clientId);
            }
            $token->setPlatform($platform);
            $token->save();
        }

        return [
            "auth"    => "success",
            "id"      => $uId,
            "mid"     => $uId,
            "user_id" => $uId,
            "sid"     => $token->getFormattedToken(),
            "secret"  => $token->getSecret(),
        ];
    }

    public function getExchangeTokensInfo(string $exchange_tokens = "", int $target_app_id = 0): array
    {
        $this->requireUser();

        $tokens = array_values(array_filter(array_map("trim", explode(",", $exchange_tokens)), fn ($token) => $token !== ""));
        if (empty($tokens)) {
            $tokens = [""];
        }

        $items = [];
        foreach ($tokens as $tok) {
            $account = null;
            if ($tok !== "") {
                $row = DB::i()->getContext()->table("im_exchange_tokens")->where("token", $tok)->fetch();
                if ($row) {
                    $account = (new Users())->get($row->user);
                }
            }
            if (!$account) {
                $account = $this->getUser();
            }

            $items[] = (object) [
                "error"                => null,
                "notification_counter" => 0,
                "tier"                 => 0,
                "profile"              => (object) [
                    "id"                     => $account->getId(),
                    "first_name"             => (string) $account->getFirstName(),
                    "last_name"              => (string) $account->getLastName(),
                    "photo_200"              => $account->getAvatarURL("normal"),
                    "screen_name"            => (string) ($account->getShortCode() ?? ("id" . $account->getId())),
                    "phone"                  => "",
                    "email"                  => "",
                    "is_banned"              => false,
                    "is_banned_forever"      => false,
                    "is_celebrity"           => false,
                    "is_deactivated"         => false,
                    "is_verified"            => (bool) $account->isVerified(),
                    "account_security_level" => 0,
                    "age_group"              => 0,
                ],
            ];
        }

        return $items;
    }

    public function getExchangeToken(string $exchange_tokens = "", int $intermediate = 0): object
    {
        $this->requireUser();
        $user = $this->getUser();

        $token = bin2hex(random_bytes(24));
        DB::i()->getContext()->table("im_exchange_tokens")->insert([
            "token"   => $token,
            "user"    => $user->getId(),
            "created" => time(),
        ]);

        return (object) [
            "users_exchange_tokens" => [(object) [
                "user_id"      => $user->getId(),
                "common_token" => $token,
                "tier_tokens"  => [],
            ]],
        ];
    }

    public function exchangeSilentAuthToken(string $token = "", string $uuid = ""): object
    {
        $row = $token === ""
            ? null
            : DB::i()->getContext()->table("im_exchange_tokens")->where("token", $token)->fetch();
        if (!$row) {
            $this->fail(28, "Invalid silent token", "internal", "exchangeSilentAuthToken");
        }

        $user = (new Users())->get($row->user);
        if (!$user) {
            $this->fail(28, "Invalid silent token", "internal", "exchangeSilentAuthToken");
        }

        $apiToken = new APIToken();
        $apiToken->setUser($user);
        $apiToken->setPlatform("edu");
        $apiToken->save();

        return (object) [
            "access_token" => $apiToken->getFormattedToken(),
            "user_id"      => $user->getId(),
        ];
    }

}
