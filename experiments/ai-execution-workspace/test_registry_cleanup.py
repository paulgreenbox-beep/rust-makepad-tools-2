"""Read-only Arbiter registry regression tests; never launch WSLC or delete staging."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('registry_storage_policy',Path(__file__).with_name('storage_policy.py'))
storage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)

def entry(rid,state='COMPLETED',session='mine',acquired=None,generation=2):
    return dict(request_id=rid,generation=generation,owner=dict(worker_id='worker',job_id='job',
        attempt_id='attempt',session_id=session,pid=100,process_birth='123456'),
        resources=['DesktopInput'],state=state,clipboard_pending=False,active_reservations=0,
        logical_background=False,queued_at=10,acquired_at=acquired,deadline=100,heartbeat=50)

def registry(entries=None,reason=''):
    entries=entries if entries is not None else [entry(1)]
    return dict(schema_version=1,next_id=max((e['request_id'] for e in entries),default=0)+2,
        entries=entries,events=[dict(timestamp=12,request=1,state='COMPLETED',reason=reason or 'done')])

class RegistryCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'resource-registry.json'
    def write(self,value):
        self.path.write_text(json.dumps(value,separators=(',',':')),encoding='utf-8')
    def observe(self,session='mine'):
        return storage._registry_lease_count(storage._read_registry_snapshot(self.path),session)
    def test_realistic_registry_larger_than_one_and_four_mib(self):
        for size in (1_100_000,4_300_000,15_000_000):
            with self.subTest(bytes=size):
                self.write(registry(reason='x'*size))
                self.assertGreater(self.path.stat().st_size,1_048_576)
                self.assertEqual(self.observe(),0)
    def test_active_lease_at_end_of_large_registry_is_not_lost(self):
        rows=[entry(i,session='other') for i in range(1,128)]
        rows.append(entry(128,'GUI_ACTIVE','mine',acquired=20))
        self.write(registry(rows,reason='x'*4_300_000))
        self.assertEqual(self.observe(),1)
        self.assertEqual(self.observe('other'),0)
    def test_unknown_or_quarantined_state_cannot_be_accepted_as_terminal(self):
        for state in ('OWNER_LOST','RECOVERING','RESOURCE_QUARANTINED','FAIL_TEST_INFRA'):
            with self.subTest(state=state):
                self.write(registry([entry(1,state,acquired=20 if state in ('RECOVERING','RESOURCE_QUARANTINED') else None)]))
                self.assertEqual(self.observe(),1)
    def test_terminal_state_with_retained_grant_never_returns_zero(self):
        self.write(registry([entry(1,'COMPLETED',acquired=20)]))
        with self.assertRaises(storage.StorageRefusal):self.observe()
    def test_duplicate_request_ids_and_invalid_generation_refuse(self):
        for rows in ([entry(1),entry(1)],[entry(1,generation=0)]):
            with self.subTest(rows=rows):
                self.write(registry(rows))
                with self.assertRaises(storage.StorageRefusal):self.observe()
    def test_duplicate_json_key_corruption_and_truncation_refuse(self):
        for raw in ('{"schema_version":1,"schema_version":1,"next_id":2,"entries":[],"events":[]}',
                    '{"schema_version":1,"next_id":2,"entries":[',b'\xff'):
            with self.subTest(raw=str(raw)[:60]):
                self.path.write_bytes(raw if isinstance(raw,bytes) else raw.encode())
                with self.assertRaises(storage.StorageRefusal):self.observe()
    def test_oversized_registry_refuses_at_native_cap(self):
        self.write(registry(reason='x'*(16*1024*1024)))
        with self.assertRaises(storage.StorageRefusal) as caught:self.observe()
        self.assertEqual(caught.exception.code,'STORAGE_RECEIPT_TOO_LARGE')
    def test_file_identity_drift_refuses_even_if_json_was_valid(self):
        self.write(registry())
        original=storage._registry_identity
        calls=[0]
        def changed(info):
            calls[0]+=1
            identity=original(info)
            return identity if calls[0]!=4 else (identity[0],identity[1]+1,*identity[2:])
        with patch.object(storage,'_registry_identity',side_effect=changed):
            with self.assertRaises(storage.StorageRefusal):self.observe()
    @unittest.skipIf(os.name=='nt','Windows denies this foreign replacement without FILE_SHARE_DELETE')
    def test_actual_foreign_replacement_during_fd_read_refuses(self):
        self.write(registry())
        original=os.fstat;calls=[0]
        def replaced(fd):
            calls[0]+=1
            if calls[0]==2:
                other=self.path.with_suffix('.replacement')
                other.write_text(json.dumps(registry()),encoding='utf-8')
                os.replace(other,self.path)
            return original(fd)
        with patch.object(storage.os,'fstat',side_effect=replaced):
            with self.assertRaises(storage.StorageRefusal):self.observe()
    def test_nonfinite_and_invalid_resource_refuse(self):
        self.path.write_text('{"schema_version":1,"next_id":2,"entries":[],"events":[],"extra":NaN}')
        with self.assertRaises(storage.StorageRefusal):self.observe()
        value=registry()
        value['entries'][0]['resources']=['UnknownDesktopResource']
        self.write(value)
        with self.assertRaises(storage.StorageRefusal):self.observe()
    def test_missing_file_never_means_zero_leases(self):
        with self.assertRaises(storage.StorageRefusal):self.observe()
    @unittest.skipUnless(os.name=='nt','native mutex exists only on Windows')
    def test_native_mutex_can_be_acquired_and_released_without_registry_mutation(self):
        with storage._arbiter_registry_lock(987654321):
            self.assertTrue(True)

if __name__=='__main__':
    unittest.main()
