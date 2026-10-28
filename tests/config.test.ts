import { spawnSync } from 'node:child_process';
import { describe, it, expect } from 'vitest';
import { loadEnv, loadModConfig, ConfigError } from '../src/config.js';

const VALID = {
  DISCORD_TOKEN: 'abc.def.ghi',
  CLIENT_ID: '123456789012345678',
  GUILD_ID: '876543210987654321',
};

describe('loadEnv', () => {
  it('aceita um ambiente válido e aplica defaults', () => {
    const cfg = loadEnv({ ...VALID });
    expect(cfg.token).toBe('abc.def.ghi');
    expect(cfg.clientId).toBe('123456789012345678');
    expect(cfg.guildId).toBe('876543210987654321');
    expect(cfg.dbPath).toBe('./vozen-helper.db');
    expect(cfg.logLevel).toBe('info');
  });

  it('lista TODAS as variáveis obrigatórias em falta numa só mensagem', () => {
    try {
      loadEnv({});
      throw new Error('devia ter lançado');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      const msg = (err as Error).message;
      expect(msg).toContain('DISCORD_TOKEN');
      expect(msg).toContain('CLIENT_ID');
      expect(msg).toContain('GUILD_ID');
    }
  });

  it('rejeita CLIENT_ID que não é um snowflake', () => {
    expect(() => loadEnv({ ...VALID, CLIENT_ID: 'not-an-id' })).toThrow(ConfigError);
  });

  it('rejeita GUILD_ID que não é um snowflake', () => {
    expect(() => loadEnv({ ...VALID, GUILD_ID: '123' })).toThrow(ConfigError);
  });

  it('respeita DB_PATH e LOG_LEVEL quando dados', () => {
    const cfg = loadEnv({ ...VALID, DB_PATH: '/data/x.db', LOG_LEVEL: 'debug' });
    expect(cfg.dbPath).toBe('/data/x.db');
    expect(cfg.logLevel).toBe('debug');
  });

  it('cai em info quando LOG_LEVEL é inválido', () => {
    const cfg = loadEnv({ ...VALID, LOG_LEVEL: 'verbose' });
    expect(cfg.logLevel).toBe('info');
  });

  it('trata espaços em branco e trata token só-espaços como em falta', () => {
    expect(() => loadEnv({ ...VALID, DISCORD_TOKEN: '   ' })).toThrow(ConfigError);
  });
});

describe('loadModConfig environment overrides', () => {
  const first = '100000000000000001';
  const second = '100000000000000002';
  const third = '100000000000000003';

  it('preserves defaults for blank variables and returns independent configurations', () => {
    const defaults = loadModConfig({});
    expect(loadModConfig({ HELPER_GENERAL_CHANNEL_ID: ' ', HELPER_MOD_ROLE_IDS: '' })).toEqual(
      defaults,
    );
    const changed = loadModConfig({});
    changed.commandChannelIds.push(first);
    expect(loadModConfig({})).toEqual(defaults);
  });

  it('uses validated IDs in settings and welcome-DM mentions without changing thresholds', () => {
    const cfg = loadModConfig({
      HELPER_COMMAND_CHANNEL_IDS: ` ${first}, ${second} `,
      HELPER_MOD_ROLE_IDS: `${second},${third}`,
      HELPER_GENERAL_CHANNEL_ID: first,
      HELPER_LOG_CHANNEL_ID: second,
      HELPER_AUTO_ROLE_ID: third,
      HELPER_SUGGESTIONS_CHANNEL_ID: second,
      HELPER_STARBOARD_CHANNEL_ID: third,
      HELPER_MEMBER_COUNTER_CHANNEL_ID: first,
      HELPER_NO_XP_CHANNEL_IDS: `${first},${third}`,
      HELPER_LEVEL_5_ROLE_ID: first,
      HELPER_LEVEL_10_ROLE_ID: second,
      HELPER_LEVEL_20_ROLE_ID: third,
      HELPER_TICKET_STAFF_ROLE_ID: second,
      HELPER_TICKET_TRANSCRIPT_CHANNEL_ID: third,
    });
    expect(cfg.commandChannelIds).toEqual([first, second]);
    expect(cfg.modRoleIds).toEqual([second, third]);
    expect(Object.values(cfg.logging.channels)).toEqual(Array(5).fill(second));
    expect(cfg.verification.autoRoleId).toBe(third);
    expect(cfg.community.suggestions.channelId).toBe(second);
    expect(cfg.community.starboard.channelId).toBe(third);
    expect(cfg.community.memberCounter.channelId).toBe(first);
    expect(cfg.community.leveling.announceChannelId).toBe(first);
    expect(cfg.community.bumpReminder.channelId).toBe(first);
    expect(cfg.community.leveling.noXpChannelIds).toEqual([first, third]);
    expect(cfg.community.leveling.levelRoles).toEqual([
      { level: 5, roleId: first },
      { level: 10, roleId: second },
      { level: 20, roleId: third },
    ]);
    expect(cfg.community.tickets.staffRoleId).toBe(second);
    expect(cfg.community.tickets.transcriptChannelId).toBe(third);
    for (const id of [first, second, third])
      expect(cfg.community.welcomeDm.message).toContain(`<#${id}>`);
    expect(cfg.spam).toEqual(loadModConfig({}).spam);
    expect(cfg.escalationLadder).toEqual(loadModConfig({}).escalationLadder);
  });

  it('rejects malformed, empty CSV entries and overflowing IDs before startup', () => {
    for (const value of ['invalid', '000000000000000000', '99999999999999999999']) {
      expect(() => loadModConfig({ HELPER_AUTO_ROLE_ID: value })).toThrow('HELPER_AUTO_ROLE_ID');
    }
    expect(() => loadModConfig({ HELPER_MOD_ROLE_IDS: `${first},,${second}` })).toThrow(
      'HELPER_MOD_ROLE_IDS',
    );
  });
});

describe('manual ticket tool configuration', () => {
  it('rejects invalid channel IDs before attempting Discord login', () => {
    for (const invalid of ['HELPER_TICKET_PANEL_CHANNEL_ID', 'HELPER_TICKET_COUNTER_CHANNEL_ID']) {
      const result = spawnSync(process.execPath, ['tools/post-ticket-panel.mjs'], {
        encoding: 'utf8',
        timeout: 5000,
        env: {
          ...process.env,
          DISCORD_TOKEN: '',
          HELPER_TICKET_PANEL_CHANNEL_ID: '100000000000000001',
          HELPER_TICKET_COUNTER_CHANNEL_ID: '100000000000000002',
          [invalid]: 'invalid',
        },
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(`${invalid} must be a valid Discord snowflake`);
    }
  });
});
