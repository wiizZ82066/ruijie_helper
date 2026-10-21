"""Explicit public-release lookup. Never downloads or executes an update."""
import json
import re
import urllib.error
import urllib.request
import urllib.parse
from utils.app_version import VERSION

RELEASES_URL = 'https://github.com/wiizZ82066/ruijie_helper/releases/latest'
API_URL = 'https://api.github.com/repos/wiizZ82066/ruijie_helper/releases/latest'


def parse_version(value):
    if not isinstance(value, str) or len(value) > 80:
        raise ValueError('Invalid version')
    match = re.fullmatch(r'v?(\d{1,5})\.(\d{1,5})\.(\d{1,5})(?:-([A-Za-z0-9.-]+))?', value)
    if not match:
        raise ValueError('Invalid version')
    return tuple(int(match[i]) for i in (1, 2, 3)), match[4]


def release_result(data, current=VERSION):
    if not isinstance(data, dict) or data.get('draft') is not False or data.get('prerelease') is not False:
        raise ValueError('Not a published stable release')
    latest, suffix = parse_version(data.get('tag_name'))
    local, local_suffix = parse_version(current)
    if suffix:
        raise ValueError('Not a stable version')
    newer = latest > local or latest == local and local_suffix is not None
    message = (f"发现新版本 {data['tag_name']}" if newer else
               '当前为本地预览版，暂无更新的正式版' if local_suffix else '当前已是最新版本')
    return {'state': 'available' if newer else 'current', 'message': message,
            'latest': data['tag_name'], 'url': RELEASES_URL}


def check_for_updates(current=VERSION):
    request = urllib.request.Request(API_URL, headers={
        'Accept': 'application/vnd.github+json', 'User-Agent': 'CampusAuthenticator',
        'X-GitHub-Api-Version': '2022-11-28'})
    try:
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                raw = response.read(512 * 1024 + 1)
        except urllib.error.HTTPError as error:
            error.close()
            if error.code not in (403, 429):
                raise
            # Public API quotas are shared by campus/proxy exits. GitHub's
            # latest-release redirect is also public and needs no API token.
            fallback = urllib.request.Request(RELEASES_URL, headers={'User-Agent': 'CampusAuthenticator'})
            with urllib.request.urlopen(fallback, timeout=8) as response:
                location = urllib.parse.urlsplit(response.url)
            prefix = '/wiizZ82066/ruijie_helper/releases/tag/'
            if (location.scheme != 'https' or location.netloc != 'github.com'
                    or not location.path.startswith(prefix) or location.query or location.fragment):
                raise ValueError('Unexpected release redirect')
            return release_result({'tag_name': location.path[len(prefix):],
                                   'draft': False, 'prerelease': False}, current)
        if len(raw) > 512 * 1024:
            raise ValueError('Oversized release response')
        return release_result(json.loads(raw), current)
    except (OSError, ValueError, TypeError):
        return {'state': 'unavailable', 'message': '暂时无法检查更新，请联网后重试或打开发布页。',
                'url': RELEASES_URL}
