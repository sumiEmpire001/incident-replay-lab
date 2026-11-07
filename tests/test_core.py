import unittest
from incident_replay import replay

class ReplayTests(unittest.TestCase):
    def event(self, user, action, time):
        return {"user":user,"action":action,"timestamp":f"2026-01-01T00:00:{time:02d}Z"}
    def test_unsorted_and_reset(self):
        events = [self.event("a","login_failure",3), self.event("a","login_failure",1),
                  self.event("a","login_failure",2), self.event("a","login_failure",4)]
        self.assertEqual(len(replay(events)), 1)
        events.insert(3, self.event("a","login_success",2))
        self.assertEqual(replay(events), [])
    def test_separate_users(self):
        events = [self.event("a","login_failure",i) for i in range(2)]
        events += [self.event("b","login_failure",i) for i in range(3)]
        self.assertEqual(replay(events)[0]["user"], "b")
    def test_invalid(self):
        with self.assertRaises(ValueError):
            replay([], threshold=0)
        with self.assertRaises(ValueError):
            replay([{"user":"a","action":"login_failure","timestamp":"2026-01-01"}])
