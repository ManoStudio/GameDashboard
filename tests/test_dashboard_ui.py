"""UI route regression checks against isolated, in-memory demo data.

Run: python -m unittest discover -s tests
"""
import io
import os
import unittest
from unittest.mock import patch

# Never initialize cloud credentials while running local UI tests.
os.environ['PYTHON_DOTENV_DISABLED'] = '1'
os.environ['type'] = ''
os.environ['ADMIN_EMAIL'] = 'ui-test@example.invalid'
os.environ['ADMIN_PASSWORD'] = 'local-ui-test-only'
import dashboard


class DashboardUITest(unittest.TestCase):
    def setUp(self):
        self.client = dashboard.app.test_client()
        with self.client.session_transaction() as session:
            session['user_email'] = 'ui-test@example.invalid'
        self.project = dashboard.demo_projects[0]['id']
        self.build = dashboard.demo_builds[self.project][0]['id']

    def test_all_views_render(self):
        for view in ['dashboard', 'projects', 'builds', 'logs', 'upload', 'build', 'log']:
            with self.subTest(view=view):
                response = self.client.get('/', query_string={'view': view, 'project': self.project,
                    'build': self.build, 'log': dashboard.demo_logs[0]['id']})
                self.assertEqual(response.status_code, 200)
                self.assertIn(b'admin-ui.js', response.data)
                self.assertIn(b'admin.css', response.data)

    def test_project_scopes_recent_logs(self):
        response = self.client.get('/', query_string={'view': 'logs', 'project': self.project})
        for log in dashboard.demo_logs:
            if log['project_id'] == self.project:
                self.assertIn(log['id'].encode(), response.data)
            else:
                self.assertNotIn(log['id'].encode(), response.data)

    def test_build_edit_and_availability(self):
        response = self.client.post(f'/builds/{self.build}/changelog', data={'changelog': '## Fixed\n- Regression check'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(dashboard.get_build(self.build)['changelog'], '## Fixed\n- Regression check')
        for enabled in ['false', 'true']:
            self.assertEqual(self.client.post(f'/builds/{self.build}/toggle', data={'enabled': enabled}).status_code, 302)
            self.assertEqual(dashboard.get_build(self.build)['enabled'], enabled == 'true')

    def test_demo_upload_manifest_and_delete(self):
        response = self.client.post(f'/projects/{self.project}/builds', data={
            'version': 'ui-test', 'channel': 'dev', 'changelog': '## Test Focus\n- Upload',
            'build': (io.BytesIO(b'local test artifact'), 'ui-test.bin'),
        }, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 302)
        build = next(build for build in dashboard.list_builds(self.project) if build['version'] == 'ui-test')
        self.assertEqual(self.client.get(f'/builds/{build["id"]}/manifest').status_code, 200)
        self.assertEqual(self.client.post(f'/builds/{build["id"]}/delete').status_code, 302)
        self.assertIsNone(dashboard.get_build(build['id']))

    def test_log_download_and_delete(self):
        log = {'id': 'ui-test-log', 'project_id': self.project, 'file_url': 'https://example.invalid/log.zip'}
        with patch.object(dashboard, 'demo_logs', [log]):
            response = self.client.get('/logs/ui-test-log/download')
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, log['file_url'])
            self.assertEqual(self.client.post('/logs/ui-test-log/delete').status_code, 302)
            self.assertIsNone(dashboard.get_log('ui-test-log'))

    def test_viewer_cannot_mutate(self):
        with patch.object(dashboard, 'current_user', return_value={'email': 'viewer@example.invalid', 'role': 'viewer'}):
            self.assertEqual(self.client.post(f'/builds/{self.build}/toggle', headers={'Accept': 'application/json'}).status_code, 403)
            response = self.client.get('/', query_string={'view': 'builds', 'project': self.project})
            self.assertNotIn(b'>Delete build<', response.data)


if __name__ == '__main__':
    unittest.main()
