import type { AgentClient } from '../AgentClient';

export function nativeHelp(client?: AgentClient): string | undefined {
  if (!client?.nativeSessions && !client?.nativeTasks) return undefined;
  return [
    'chat uses the resident owner conversation',
    '/hello /balance /topup /start /stop /reset /settings /cred /think /clear /compact',
    ...(client.nativeSessions ? [
      '/sessions · /session new · /session resume|fork <id> · /session show <id>',
      '/session prompt <id> <text> · /session cancel <id> · /session events <id>',
    ] : []),
    ...(client.nativeTasks ? [
      '/tasks · /task new <JSON body> · /task input <id> <text>',
      '/task start|archive|cancel <id> · /task answer <id> <JSON body>',
      '/task show|events <id>',
      client.task || client.taskInfo
        ? '/result [id] · /cancel [id|all] keep their existing owner-turn meaning'
        : '/result <id> · /cancel <id> are native task aliases',
    ] : []),
    'native events show the resource event stream; Esc stops watching',
    '/agentlog /startuplog /signatures /back /quit',
  ].join('\n');
}

/** Returns true only for a supported native command. No client-side task store. */
export async function nativeCommand(client: AgentClient | undefined, line: string,
  out: (text: string) => void, signal?: AbortSignal): Promise<boolean> {
  const show = (value: unknown) => out(`${JSON.stringify(value, null, 2)}\n`);
  if (line === '/sessions' && client?.nativeSessions) { show(await client.nativeSessions.list()); return true; }
  if (line === '/tasks' && client?.nativeTasks) { show(await client.nativeTasks.list()); return true; }
  const match = /^\/(session|task|result|cancel)(?:\s+(.*))?$/.exec(line);
  if (!match) return false;
  const [, kind, rest = ''] = match;
  const sessions = client?.nativeSessions, tasks = client?.nativeTasks;
  if (kind === 'result' || kind === 'cancel') {
    if (!tasks) return false;
    // The proxy can synthesize Responses alongside native zgh tasks. Keep
    // those existing turn ids and "latest" behavior in the ordinary CLI.
    if (client?.task || client?.taskInfo) return false;
    if (!rest || rest === 'all') throw new Error(`/${kind} requires one native task id`);
    show(await (kind === 'result' ? tasks.get(rest) : tasks.cancel(rest))); return true;
  }
  if (kind === 'session' && !sessions || kind === 'task' && !tasks) return false;
  const [action = '', id = ''] = rest.split(/\s+/, 2);
  const text = rest.replace(/^\S+\s+\S+\s*/, '');
  const api = kind === 'session' ? sessions! : tasks!;
  if (action === 'new') {
    show(await (kind === 'session' ? sessions!.create() : tasks!.create(JSON.parse(rest.slice(3).trim())))); return true;
  }
  if (!id) throw new Error(`/${kind} requires an action and id; /help lists supported commands`);
  switch (action) {
    case 'show': show(await api.get(id)); break;
    case 'cancel': show(await api.cancel(id)); break;
    case 'resume': case 'fork':
      if (kind !== 'session') throw new Error('resume/fork applies to sessions');
      show(await sessions!.create({ [action]: id })); break;
    case 'prompt':
      if (kind !== 'session' || !text || text === rest) throw new Error('/session prompt <id> <text>');
      show(await sessions!.prompt(id, text)); break;
    case 'input':
      if (kind !== 'task' || !text || text === rest) throw new Error('/task input <id> <text>');
      show(await tasks!.input(id, text)); break;
    case 'start': case 'archive':
      if (kind !== 'task') throw new Error('start/archive applies to tasks');
      show(await tasks![action](id)); break;
    case 'answer':
      if (kind !== 'task') throw new Error('answer applies to tasks');
      show(await tasks!.answer(id, JSON.parse(text))); break;
    case 'events':
      try { for await (const event of api.events(id, { signal })) show(event); }
      catch (e) { if (!signal?.aborted) throw e; }
      break;
    default: throw new Error(`unknown /${kind} action; /help lists supported commands`);
  }
  return true;
}
