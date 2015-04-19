-- PAM authentication for Prosody
-- Copyright (C) 2013 Kim Alvefur
--
-- Requires https://github.com/devurandom/lua-pam
-- and LuaPosix

local posix = require "posix";
local pam = require "pam";
local new_sasl = require "util.sasl".new;
local my_host = module.host;

function new_default_provider(host)
	local provider = { name = "pam" };
	log("debug", "initializing pam authentication provider for host '%s'", host);

	function provider.test_password(username, password)
		log("debug", "test password '%s' for user %s at host %s", password, username, module.host);

		local h, err = pam.start("xmpp", username, {
			function (t)
				if #t == 1 and t[1][1] == pam.PROMPT_ECHO_OFF then
					return { { password, 0} };
				end
			end
		});
		if h and h:authenticate() and h:endx(pam.SUCCESS) then
			return true, true;
		end
		return nil, "Auth failed.";
	end

	function provider.user_exists(username)
		local account = posix.getpasswd(username);
		if not account then
			log("debug", "account not found for username '%s' at host '%s'", username, module.host);
			return nil, "Auth failed. Invalid username";
		end
		return true;
	end

	function provider.get_sasl_handler(session)
		local testpass_authentication_profile = {
			plain_test = function(sasl, ...)
				return provider.test_password(...)
			end,
			order = {"plain_test"},
			session = session,
			host = my_host
		};
		return new_sasl(module.host, testpass_authentication_profile);
	end

	return provider;
end

module:add_item("auth-provider", new_default_provider(module.host));
