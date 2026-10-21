import io
import unittest
from unittest.mock import patch
from utils import update_check as updates


class UpdateTests(unittest.TestCase):
    def release(self, tag):
        return {'tag_name': tag, 'draft': False, 'prerelease': False}

    def test_numeric_comparison(self):
        self.assertEqual(updates.release_result(self.release('v6.10.0'), '6.9.9')['state'], 'available')
        self.assertEqual(updates.release_result(self.release('v6.2.2'), '6.2.2')['state'], 'current')
        self.assertEqual(updates.release_result(self.release('v6.2.1'), '6.2.2')['state'], 'current')

    def test_preview_becomes_stable_without_offering_downgrade(self):
        self.assertEqual(updates.release_result(self.release('v6.2.3'), '6.2.3-preview')['state'], 'available')
        self.assertEqual(updates.release_result(self.release('v6.2.2'), '6.2.3-preview')['state'], 'current')

    def test_draft_preview_and_invalid_tags_are_rejected(self):
        for data in (dict(self.release('v6.2.3'), draft=True),
                     dict(self.release('v6.2.3'), prerelease=True),
                     self.release('v6.2.3-beta'), self.release('https://example.org/'), []):
            with self.assertRaises(ValueError):
                updates.release_result(data)

    def test_remote_urls_are_not_trusted(self):
        data = dict(self.release('v7.0.0'), html_url='https://example.org/fake.exe')
        self.assertEqual(updates.release_result(data)['url'], updates.RELEASES_URL)

    def test_public_page_fallback_when_api_rate_limited(self):
        error = updates.urllib.error.HTTPError(updates.API_URL, 403, 'limited', {}, None)
        page = io.BytesIO(b'')
        page.url = 'https://github.com/wiizZ82066/ruijie_helper/releases/tag/v6.2.3'
        with patch.object(updates.urllib.request, 'urlopen', side_effect=[error, page]):
            self.assertEqual(updates.check_for_updates('6.2.2')['state'], 'available')

    def test_fallback_rejects_another_repository(self):
        error = updates.urllib.error.HTTPError(updates.API_URL, 429, 'limited', {}, None)
        page = io.BytesIO(b'')
        page.url = 'https://github.com/other/repo/releases/tag/v9.0.0'
        with patch.object(updates.urllib.request, 'urlopen', side_effect=[error, page]):
            self.assertEqual(updates.check_for_updates()['state'], 'unavailable')

    def test_network_and_bad_json_are_not_reported_as_up_to_date(self):
        with patch.object(updates.urllib.request, 'urlopen', side_effect=OSError('private proxy details')):
            result = updates.check_for_updates()
            self.assertEqual(result['state'], 'unavailable')
            self.assertNotIn('private', result['message'])
        with patch.object(updates.urllib.request, 'urlopen', return_value=io.BytesIO(b'not json')):
            self.assertEqual(updates.check_for_updates()['state'], 'unavailable')
