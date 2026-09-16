import http from 'k6/http';
import { check, fail } from 'k6';

const vus = parseInt(__ENV.VEIL_VUS || '50', 10);

export const options = {
  stages: [
    { duration: '30s', target: Math.max(1, Math.floor(vus / 5)) },
    { duration: '1m', target: vus },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<1000'],
    checks: ['rate==1'],
  },
};

const origin = __ENV.VEIL_ORIGIN || 'http://127.0.0.1:8080';
const token = __ENV.VEIL_AGENT_TOKEN;
const item = __ENV.VEIL_ITEM_ID;
const upstream = __ENV.VEIL_UPSTREAM_URL || 'https://httpbin.org/get';

export default function () {
  if (!token || !item) {
    fail('VEIL_AGENT_TOKEN and VEIL_ITEM_ID are required');
  }

  const res = http.post(
    `${origin}/v1/use`,
    JSON.stringify({ item, url: upstream, method: 'GET' }),
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      timeout: '15s',
    }
  );

  check(res, {
    'status is 200': (r) => r.status === 200,
    'decision is allow': (r) => {
      try {
        return r.json('decision') === 'allow';
      } catch {
        return false;
      }
    },
  });
}
