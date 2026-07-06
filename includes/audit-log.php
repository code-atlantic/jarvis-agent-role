<?php
/**
 * Audit log for the Jarvis agent user.
 *
 * Primary capture is at the **Abilities API layer**: the WordPress Abilities API
 * fires `wp_before_execute_ability` / `wp_after_execute_ability` around every
 * ability execution, so hooking those two actions logs every MCP/agent tool call
 * — ours, the core mcp-adapter's, FluentBoards/CRM adapters, and any custom tool
 * added later — with tool name, full input, and result. No per-event guessing, no
 * patching core or vendor files.
 *
 * Auth events (cookie login, application-password) don't run through an ability,
 * so they're captured separately.
 *
 * WP-CLI commands are captured too, but UNCONDITIONALLY (not gated on the jarvis
 * role) — every `wp` command is privileged shell access worth auditing, and it
 * usually runs with no `--user`, so there's no jarvis actor to gate on. This is
 * the site-side trail for maintenance done over SSH.
 *
 * Ability + auth logging only fires for users on the `jarvis_agent` role, so human
 * admins and non-agent API clients generate nothing there.
 *
 * Storage: JSON-lines file, one event per line. Defaults ABOVE the web root when
 * that location is writable (so the trail isn't web-reachable), else wp-content.
 * Override with the JARVIS_AUDIT_LOG_FILE constant.
 *
 * @package CodeAtlantic\Jarvis
 */

namespace CodeAtlantic\Jarvis\Audit;

use const CodeAtlantic\Jarvis\ROLE_SLUG;

defined( 'ABSPATH' ) || exit;

/** Truncate the log once it exceeds this size (bytes). Keeps growth bounded. */
const MAX_LOG_BYTES = 10485760; // 10 MB.

/**
 * Input/result keys whose VALUES are redacted even in this internal log.
 * Logging a freshly-minted password or app-password plaintext would be a
 * self-inflicted wound regardless of who can read the file. Names matched
 * case-insensitively, substring. Everything else is logged in full.
 */
const REDACT_KEYS = [ 'password', 'pwd', 'secret', 'token', 'app_password', 'application_password', 'private_key', 'api_key' ];

/**
 * Absolute path to the audit log file.
 *
 * Resolution order:
 *   1. JARVIS_AUDIT_LOG_FILE constant, if defined.
 *   2. A `jarvis-audit/` dir one level above WP_CONTENT_DIR (typically above the
 *      web root) when that parent is writable — keeps the trail non-web-reachable.
 *   3. Fallback: inside WP_CONTENT_DIR.
 */
function log_file(): string {
	if ( defined( 'JARVIS_AUDIT_LOG_FILE' ) ) {
		return JARVIS_AUDIT_LOG_FILE;
	}

	$above = dirname( WP_CONTENT_DIR ) . '/jarvis-audit';
	if ( is_dir( $above ) || @mkdir( $above, 0750, true ) || is_writable( dirname( WP_CONTENT_DIR ) ) ) {
		if ( is_dir( $above ) && is_writable( $above ) ) {
			return $above . '/jarvis-audit.log';
		}
	}

	return WP_CONTENT_DIR . '/jarvis-audit.log';
}

/**
 * Is the current actor a Jarvis agent user? Logging is a no-op for everyone else.
 *
 * @param \WP_User|null $user Optional explicit user (for hooks where the current
 *                            user isn't set yet, e.g. auth events).
 */
function actor_is_jarvis( $user = null ): bool {
	$user = $user ?: wp_get_current_user();
	return $user && $user->exists() && in_array( ROLE_SLUG, (array) $user->roles, true );
}

/**
 * Recursively redact sensitive values by key name. Preserves structure so the
 * shape of the call is still auditable; just blanks the dangerous leaves.
 *
 * @param mixed $data
 * @return mixed
 */
function redact( $data ) {
	if ( ! is_array( $data ) ) {
		return $data;
	}
	$out = [];
	foreach ( $data as $key => $value ) {
		$lower = is_string( $key ) ? strtolower( $key ) : '';
		$hit   = false;
		foreach ( REDACT_KEYS as $needle ) {
			if ( '' !== $lower && false !== strpos( $lower, $needle ) ) {
				$hit = true;
				break;
			}
		}
		$out[ $key ] = $hit ? '«redacted»' : redact( $value );
	}
	return $out;
}

/**
 * Append one event to the audit log for the Jarvis actor.
 *
 * @param string              $action  Short verb, e.g. 'ability', 'auth.login'.
 * @param array<string,mixed> $context Structured detail.
 * @param \WP_User|null       $user    Explicit user when current-user isn't ready.
 */
function record( string $action, array $context = [], $user = null ): void {
	if ( ! actor_is_jarvis( $user ) ) {
		return;
	}

	$user = $user ?: wp_get_current_user();

	$entry = [
		'time'    => gmdate( 'c' ), // ISO-8601 UTC; unambiguous across sites.
		'user'    => $user->user_login,
		'user_id' => $user->ID,
		'action'  => $action,
		'ip'      => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
		'context' => $context,
	];

	write_line( wp_json_encode( $entry ) );
}

/**
 * Append a raw line to the log, rotating first if oversized. Failures are
 * swallowed — audit logging must never break the request it's observing.
 */
function write_line( string $line ): void {
	$file = log_file();

	if ( file_exists( $file ) && filesize( $file ) > MAX_LOG_BYTES ) {
		@rename( $file, $file . '.1' );
	}

	// LOCK_EX so concurrent writes don't interleave.
	@file_put_contents( $file, $line . "\n", FILE_APPEND | LOCK_EX );
}

/**
 * Trim a value for logging so a giant blob (e.g. full block HTML) doesn't bloat
 * the line. Internal log, so the cap is generous. Arrays are redacted+returned
 * as-is; long strings are truncated with a marker.
 *
 * @param mixed $value
 * @return mixed
 */
function clip( $value ) {
	if ( is_string( $value ) && strlen( $value ) > 20000 ) {
		return substr( $value, 0, 20000 ) . '…[' . strlen( $value ) . ' bytes]';
	}
	return $value;
}

/* -------------------------------------------------------------------------
 * Primary capture: every ability execution.
 *
 * `wp_before_execute_ability` ( $name, $input )
 * `wp_after_execute_ability`  ( $name, $input, $result )
 *
 * We log on *after* so we can record the outcome (ok/error) in one line. Only
 * the INPUT is recorded — the call's intent and arguments are the audit signal.
 * Result bodies are deliberately NOT logged (a read tool's payload is noise; for
 * write/delete/update tools the input args already capture what changed). On
 * failure we keep the WP_Error code+message, since "it failed, and why" is signal.
 * Input is redacted for credential keys and clipped for size.
 * ---------------------------------------------------------------------- */
add_action(
	'wp_after_execute_ability',
	function ( $name, $input, $result ) {
		if ( ! actor_is_jarvis() ) {
			return;
		}

		$entry = [
			'tool'   => $name,
			'input'  => redact( is_array( $input ) ? array_map( __NAMESPACE__ . '\\clip', $input ) : $input ),
			'status' => is_wp_error( $result ) ? 'error' : 'ok',
		];

		if ( is_wp_error( $result ) ) {
			$entry['error'] = [
				'code'    => $result->get_error_code(),
				'message' => $result->get_error_message(),
			];
		}

		record( 'ability', $entry );
	},
	10,
	3
);

/* -------------------------------------------------------------------------
 * Auth events — these don't flow through an ability, so capture directly.
 * ---------------------------------------------------------------------- */

/**
 * Cookie login for the Jarvis user.
 */
add_action(
	'wp_login',
	function ( $user_login, $user ) {
		record( 'auth.login', [ 'method' => 'cookie' ], $user );
	},
	10,
	2
);

/**
 * Application-password REST authentication — the agent's primary connection path.
 */
add_action(
	'application_password_did_authenticate',
	function ( $user, $item ) {
		record(
			'auth.app_password',
			[ 'app' => isset( $item['name'] ) ? $item['name'] : '' ],
			$user
		);
	},
	10,
	2
);

/* -------------------------------------------------------------------------
 * WP-CLI command capture.
 *
 * Every `wp` command run against this site is privileged shell access, so it's
 * logged UNCONDITIONALLY — NOT gated on the jarvis WP role. Rationale: operators
 * (and the agent) usually run `wp @site …` with no `--user=jarvis`, so from the
 * site's perspective there's no jarvis actor; but the *channel* (someone with
 * shell + wp-cli) is exactly what needs auditing. This is the site-side trail
 * that catches maintenance done over SSH that never touches an ability or REST.
 *
 * Uses `before_invoke:` (fires just before a command runs, with the full command
 * resolved) and captures the runtime + exit via a shutdown record on `after_invoke:`.
 * We log the command, subcommand, args, the resolved --user (if any), and the OS
 * user/host so the trail ties back to who was on the box.
 * ---------------------------------------------------------------------- */
if ( defined( 'WP_CLI' ) && WP_CLI ) {

	/**
	 * Log a wp-cli invocation. Bypasses actor_is_jarvis() on purpose — see above.
	 *
	 * @param string               $phase      Event phase label (e.g. 'run').
	 * @param array<int,string>    $args       Positional command args from the hook.
	 * @param array<string,mixed>  $assoc_args Associative --flags from the hook.
	 */
	$jarvis_cli_logger = function ( string $phase, array $args = [], array $assoc_args = [] ) {
		// Prefer the hook-provided args; fall back to raw argv if empty.
		if ( ! empty( $args ) ) {
			$parts = $args;
			foreach ( $assoc_args as $k => $v ) {
				$parts[] = ( true === $v ) ? "--$k" : "--$k=$v";
			}
		} else {
			$parts = array_slice( (array) ( $GLOBALS['argv'] ?? [] ), 1 );
		}

		// Resolve --user if the caller passed one (who the command RAN AS in WP).
		$run_as = '';
		try {
			$runner = method_exists( '\WP_CLI', 'get_runner' ) ? \WP_CLI::get_runner() : null;
			if ( $runner && ! empty( $runner->config['user'] ) ) {
				$run_as = (string) $runner->config['user'];
			}
		} catch ( \Throwable $e ) {
			$run_as = '';
		}

		$command = implode( ' ', array_map( 'strval', $parts ) );

		// Scrub secret-shaped values out of the command STRING itself, e.g.
		// `wp config set SOME_SECRET abc123` or `wp user create x --user_pass=hunter2`.
		// Redact the token following a secret-ish flag/word.
		$command = preg_replace(
			'/(\b\S*(?:password|secret|token|api[_-]?key|private[_-]?key)\S*\b[=\s]+)(\S+)/i',
			'$1«redacted»',
			$command
		);

		$entry = [
			'time'     => gmdate( 'c' ),
			'action'   => 'wpcli.' . $phase,
			// OS-level identity of who ran the command (ties to SSH access).
			'os_user'  => function_exists( 'posix_getpwuid' ) && function_exists( 'posix_geteuid' )
				? ( posix_getpwuid( posix_geteuid() )['name'] ?? get_current_user() )
				: get_current_user(),
			'ssh_from' => isset( $_SERVER['SSH_CLIENT'] )
				? sanitize_text_field( wp_unslash( $_SERVER['SSH_CLIENT'] ) )
				: ( (string) ( getenv( 'SSH_CLIENT' ) ?: '' ) ),
			'run_as'   => $run_as, // WP --user, if any.
			'cwd'      => getcwd() ?: '',
			'command'  => clip( $command ),
		];

		write_line( wp_json_encode( $entry ) );
	};

	// `before_run_command` is WP-CLI's GLOBAL pre-command hook — fires before
	// every command with ( $args, $assoc_args, $options ). (`before_invoke`
	// requires a per-command suffix and won't fire globally.) We log here; that's
	// the one guaranteed-to-fire point for every invocation.
	\WP_CLI::add_hook(
		'before_run_command',
		function ( $args = [], $assoc_args = [], $options = [] ) use ( $jarvis_cli_logger ) {
			$jarvis_cli_logger( 'run', $args, $assoc_args );
		}
	);
}

/* -------------------------------------------------------------------------
 * WP-CLI: `wp jarvis audit [--lines=N]` to tail the trail.
 * ---------------------------------------------------------------------- */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command(
		'jarvis audit',
		function ( $args, $assoc_args ) {
			$file = log_file();
			if ( ! file_exists( $file ) ) {
				\WP_CLI::warning( 'No audit log yet at ' . $file );
				return;
			}
			$lines = isset( $assoc_args['lines'] ) ? max( 1, (int) $assoc_args['lines'] ) : 20;
			$all   = file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
			foreach ( array_slice( $all, -$lines ) as $line ) {
				\WP_CLI::line( $line );
			}
			\WP_CLI::log( "\n" . $file );
		}
	);
}
