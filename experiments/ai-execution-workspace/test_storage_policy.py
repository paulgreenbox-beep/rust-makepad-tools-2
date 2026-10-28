"""Policy/real disposable host-file tests; no WSLC, App, models or hard-quota claims."""
import importlib.util,json,os,tempfile,unittest,subprocess
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('owning_storage_policy',Path(__file__).with_name('storage_policy.py'))
storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(storage)

class StoragePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.runtime=self.root/'attempt';self.runtime.mkdir()
    def hard_policy(self):
        p=storage.policy()
        for key in ('storage_enforcement','hard_quota_enforced','approved_soft_profile','max_scenario_growth_bytes',
                    'max_single_growth_bytes','max_host_evidence_bytes','max_capture_count'):p.pop(key,None)
        p.update(schema='toolkit-wslc-storage-policy-v1',policy_id='TOOLKIT_WSLC_STORAGE_POLICY_V1',version=1,require_hard_quota_before_create=True)
        return p
    def write(self,name,value):
        (self.runtime/name).write_text(json.dumps(value),encoding='utf-8')
    def fixture(self):
        original=self.root/'approved-ELF';original.write_bytes(b'\x7fELFunique-approved-payload')
        staged=self.runtime/'ai-workspace-fixture';staged.write_bytes(original.read_bytes())
        self.write('stage-linux-fixture.json',{'source':str(original),'target':str(staged),
            'bytes':staged.stat().st_size,'sha256':storage.digest(staged)})
        self.write('bootstrap-failure.json',{'status':'FAILED_TRANSFER_RAW_RECEIPT'})
        self.write('source-build-manifest.json',{'preserve':'unique source receipt'})
        return original,staged
    def cleanup(self,**changes):
        args=dict(identity_verified=True,terminal=True,active_leases=0,container_absent=True);args.update(changes)
        with patch.object(storage,'EVIDENCE',self.root):return storage.cleanup_staging(self.runtime,**args)
    def test_exact_decimal_cap_no_eager_allocation(self):
        p=storage.policy();self.assertEqual(p['container_storage_max_bytes'],120_000_000_000)
        self.assertFalse(p['eager_allocation']);self.assertFalse(p['delete_foreign_resources'])
    def test_threshold_boundaries_and_host_reserve_are_independent(self):
        for used,level in [(0,'NORMAL'),(95_999_999_999,'NORMAL'),(96_000_000_000,'WARNING'),
                           (107_999_999_999,'WARNING'),(108_000_000_000,'CLEANUP_REFUSE_HEAVY'),
                           (113_999_999_999,'CLEANUP_REFUSE_HEAVY'),(114_000_000_000,'STOP_GROWTH')]:
            with self.subTest(used=used):
                self.assertEqual(storage.decide(used,20_000_000_000,'observe')['level'],level)
        for operation in ('create','stage','build','upload','grow'):
            self.assertEqual(storage.decide(0,9_999_999_999,operation)['code'],'HOST_STORAGE_RESERVE_REFUSED')
        self.assertEqual(storage.decide(0,10_000_000_000,'stage',incoming_bytes=1)['code'],'HOST_STORAGE_RESERVE_REFUSED')
    def test_90_and_95_percent_refuse_growth_without_interrupting_mutation(self):
        self.assertEqual(storage.decide(108_000_000_000,20_000_000_000,'upload')['code'],'STORAGE_HEAVY_OPERATION_REFUSED')
        decision=storage.decide(114_000_000_000,20_000_000_000,'grow')
        self.assertEqual(decision['code'],'STORAGE_GROWTH_REFUSED')
        self.assertFalse(decision['automatic_retry_allowed']);self.assertFalse(decision['mutation_interruption_authorized'])
    def test_synthetic_enforcement_witness_required_in_actual_admission_path(self):
        legacy=self.hard_policy()
        patcher=patch.object(storage,'policy',return_value=legacy);patcher.start();self.addCleanup(patcher.stop)
        q={'hard_limit_enforced':True,'limit_readback_bytes':120_000_000_000,
           'covers_all_writable_mounts':True,'kernel_write_refusal_observed':True,'eager_allocation':False}
        self.assertEqual(storage.decide(0,20_000_000_000,'create',quota=q)['status'],'ADMITTED')
        for key in q:
            missing=dict(q);missing.pop(key)
            self.assertEqual(storage.decide(0,20_000_000_000,'create',quota=missing)['code'],'STORAGE_QUOTA_UNSUPPORTED')
        for value in [None,{}, {'hard_limit_enforced':True},{**q,'limit_readback_bytes':120*1024**3},
                      {**q,'covers_all_writable_mounts':False},{**q,'eager_allocation':True}]:
            self.assertEqual(storage.decide(0,20_000_000_000,'create',quota=value)['code'],'STORAGE_QUOTA_UNSUPPORTED')
    def test_boolean_or_negative_measurement_is_not_zero(self):
        for bad in (True,-1,None,'120'):
            with self.subTest(bad=bad),self.assertRaises(storage.StorageRefusal):storage.decide(bad,20_000_000_000,'grow')
        self.assertEqual(storage.decide(119_000_000_000,20_000_000_000,'grow',incoming_bytes=2_000_000_000)['code'],'STORAGE_GROWTH_REFUSED')
    def test_failed_transfer_deletes_only_exact_reproducible_host_copy(self):
        original,staged=self.fixture();result=self.cleanup()
        self.assertEqual(result['status'],'DISPOSABLE_STAGING_CLEANED');self.assertFalse(staged.exists())
        self.assertTrue(original.exists());self.assertTrue((self.runtime/'bootstrap-failure.json').exists())
        self.assertTrue((self.runtime/'source-build-manifest.json').exists())
        self.assertEqual(result['deleted_bytes'],len(original.read_bytes()))
    def test_complete_transfer_source_preserved_for_core_reverification(self):
        _,staged=self.fixture();self.write('fixture-upload.json',{'exit_code':0})
        self.assertEqual(self.cleanup()['status'],'PRESERVED_CORE_REFERENCE');self.assertTrue(staged.exists())
    def test_active_lease_live_container_or_unverified_owner_never_deletes(self):
        _,staged=self.fixture()
        for change in ({'identity_verified':False},{'terminal':False},{'active_leases':1},
                       {'active_leases':False},{'container_absent':False}):
            with self.subTest(change=change),self.assertRaisesRegex(storage.StorageRefusal,'CLEANUP_IDENTITY_NOT_VERIFIED'):
                self.cleanup(**change)
            self.assertTrue(staged.exists())
    def test_substituted_source_path_or_foreign_bytes_refused(self):
        original,staged=self.fixture();original.write_bytes(b'foreign-new-content')
        with self.assertRaisesRegex(storage.StorageRefusal,'CLEANUP_IDENTITY_NOT_VERIFIED'):self.cleanup()
        self.assertTrue(staged.exists())
    def test_hardlink_and_path_escape_are_refused(self):
        _,staged=self.fixture();os.link(staged,self.root/'foreign-link')
        with self.assertRaisesRegex(storage.StorageRefusal,'CLEANUP_IDENTITY_NOT_VERIFIED'):self.cleanup()
        with self.assertRaisesRegex(storage.StorageRefusal,'STORAGE_PATH_ESCAPE'):
            storage.safe_path(self.root.parent/'outside',self.root,must_exist=False)
    def test_reparse_substitution_refuses_before_disposition(self):
        outside=self.root/'other-owned-directory';outside.mkdir();(outside/'sentinel').write_text('keep')
        staged=self.runtime/'ai-workspace-fixture'
        pwsh=Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/native/powershell/pwsh.exe'
        quote=lambda p:"'"+str(p).replace("'","''")+"'"
        subprocess.run([str(pwsh),'-NoProfile','-Command',
            'New-Item -ItemType Junction -Path '+quote(staged)+' -Target '+quote(outside)+' | Out-Null'],
            capture_output=True,check=True,timeout=10)
        self.addCleanup(lambda:staged.rmdir() if staged.exists() else None)
        with patch.object(storage,'remove_exact_file') as delete:
            with self.assertRaisesRegex(storage.StorageRefusal,'STORAGE_REPARSE_REFUSED'):self.cleanup()
            delete.assert_not_called()
        self.assertEqual((outside/'sentinel').read_text(),'keep')
    def test_changed_file_identity_refuses_native_delete_handle(self):
        _,staged=self.fixture();info=staged.stat()
        with self.assertRaisesRegex(storage.StorageRefusal,'CLEANUP_IDENTITY_NOT_VERIFIED'):
            storage.remove_exact_file(staged,(info.st_dev,info.st_ino+1,info.st_size,info.st_mtime_ns),storage.digest(staged))
        self.assertTrue(staged.exists())
    def test_real_creator_path_stops_before_any_staging_when_quota_missing(self):
        observation={'hard_limit_enforced':False,'code':'STORAGE_QUOTA_UNSUPPORTED'}
        with patch.object(storage,'EVIDENCE',self.root),patch.object(storage,'probe',return_value=observation),patch.object(storage,'policy',return_value=self.hard_policy()):
            value=storage.admit_create(self.runtime/'admission')
        self.assertEqual(value['decision']['code'],'STORAGE_QUOTA_UNSUPPORTED')
        self.assertFalse(value['container_created']);self.assertFalse(value['staging_started'])
        self.assertEqual(list((self.runtime/'admission').iterdir()),[self.runtime/'admission/storage-admission.json'])
    def soft_witness(self):
        return {'storage_enforcement':'monitored_soft_limit','hard_limit_enforced':False,'limit_readback_bytes':None,
            'profile':'focus_trace71','usage_status':'NEW_OWNED_CONTAINER_NOT_YET_CREATED',
            'inventory_verified':True,'guest_process_inventory_verified':True,'size_observation_available':True,
            'unexpected_writable_mounts':False,'scenario_growth_budget_bytes':1073741824,'eager_allocation':False}
    def test_soft_create_preserves_unobserved_usage_as_null_and_never_hard_pass(self):
        result=storage.decide(None,20_000_000_000,'create',quota=self.soft_witness())
        self.assertEqual(result['status'],'ADMITTED');self.assertIsNone(result['usage_bytes'])
        self.assertEqual(result['level'],'NEW_CONTAINER_NOT_YET_CREATED');self.assertFalse(result['hard_quota_enforced'])
        for key in self.soft_witness():
            q=self.soft_witness();q.pop(key)
            with self.subTest(key=key):self.assertEqual(storage.decide(None,20_000_000_000,'create',quota=q)['status'],'REFUSED')
        self.assertEqual(storage.decide(None,10_000_000_000,'create',quota=self.soft_witness())['code'],'HOST_STORAGE_RESERVE_REFUSED')
        for operation in ('grow','upload','stage'):
            with self.assertRaisesRegex(storage.StorageRefusal,'USAGE_NOT_VERIFIED'):storage.decide(None,20_000_000_000,operation)
    def test_policy_versions_missing_policy_unknown_mode_and_changed_bytes_fail(self):
        original=Path(storage.HERE/'storage-policy.json').read_text()
        for change in ({'version':'1.2'},{'schema':'unknown'},{'storage_enforcement':'unchecked'},
                       {'hard_quota_enforced':True},{'host_ssd_reserve_bytes':0}):
            p=json.loads(original);p.update(change)
            with patch.object(storage,'read',return_value=p),self.assertRaisesRegex(storage.StorageRefusal,'STORAGE_POLICY_INVALID'):storage.policy()
        with patch.object(storage,'HERE',self.root),self.assertRaisesRegex(storage.StorageRefusal,'STORAGE_POLICY_UNAVAILABLE'):storage.policy()
    def actual_size(self):
        ctx={'container_id':'a'*64,'image':'sha256:'+'b'*64,'exclusive_owner':'owner','exclusive_nonce':'c'*32,
            'container_created':'2026-10-27T12:00:00Z','container_started_at':'2026-10-27T12:00:01Z',
            'fixture_sha256':'9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB'}
        actual={'Id':ctx['container_id'],'Image':ctx['image'],'Created':ctx['container_created'],
            'State':{'StartedAt':ctx['container_started_at']},'Config':{'Labels':{'aiui.toolkit.owner':'owner','aiui.toolkit.nonce':'c'*32}},
            'Mounts':[],'HostConfig':{},'SizeRw':100,'SizeRootFs':9999}
        return actual,ctx
    def test_actual_size_parser_binds_exact_container_nonce_incarnation_and_separate_scopes(self):
        actual,ctx=self.actual_size();result=storage.growth_decision(actual,ctx,incoming_bytes=100)
        self.assertEqual(result['observation']['writable_layer_bytes'],100)
        self.assertFalse(result['observation']['shared_rootfs_attributed_to_container'])
        for field in ('Id','Image','Created'):
            actual,ctx=self.actual_size();actual[field]='foreign'
            with self.subTest(field=field),self.assertRaisesRegex(storage.StorageRefusal,'CLEANUP_IDENTITY_NOT_VERIFIED'):
                storage.growth_decision(actual,ctx,incoming_bytes=100)
        for key in ('aiui.toolkit.owner','aiui.toolkit.nonce'):
            actual,ctx=self.actual_size();actual['Config']['Labels'][key]='foreign'
            with self.assertRaisesRegex(storage.StorageRefusal,'CLEANUP_IDENTITY_NOT_VERIFIED'):storage.growth_decision(actual,ctx,incoming_bytes=100)
        actual,ctx=self.actual_size();actual['State']['StartedAt']='old'
        with self.assertRaises(storage.StorageRefusal):storage.growth_decision(actual,ctx,incoming_bytes=100)
    def test_unknown_usage_changed_artifact_unbounded_request_and_mount_refuse(self):
        for value in (None,True,'0',-1):
            actual,ctx=self.actual_size();actual['SizeRw']=value
            with self.assertRaisesRegex(storage.StorageRefusal,'USAGE_NOT_VERIFIED'):storage.growth_decision(actual,ctx,incoming_bytes=1)
        actual,ctx=self.actual_size();ctx['fixture_sha256']='D'*64
        with self.assertRaisesRegex(storage.StorageRefusal,'STORAGE_ARTIFACT_IDENTITY_CHANGED'):storage.growth_decision(actual,ctx,incoming_bytes=1)
        actual,ctx=self.actual_size()
        with self.assertRaisesRegex(storage.StorageRefusal,'UNBOUNDED_GUEST_WRITE_REQUEST'):storage.growth_decision(actual,ctx,incoming_bytes=536870913)
        actual['Mounts']=[{'Source':'foreign'}]
        with self.assertRaisesRegex(storage.StorageRefusal,'UNEXPECTED_WRITABLE_MOUNT'):storage.growth_decision(actual,ctx,incoming_bytes=1)
        actual,ctx=self.actual_size();actual['SizeRw']=1073741824
        with self.assertRaisesRegex(storage.StorageRefusal,'STORAGE_SCENARIO_BUDGET_REFUSED'):storage.growth_decision(actual,ctx,incoming_bytes=1)
    def test_real_soft_producer_keeps_refusal_and_no_container_when_native_observation_fails(self):
        with patch.object(storage,'fixed_query',return_value={'exit_code':1,'stderr':'native failure'}),patch.object(storage,'EVIDENCE',self.root):
            value=storage.admit_create(self.runtime/'soft-admission','focus_trace71')
        self.assertEqual(value['decision']['code'],'BLOCKED_EXISTING_RUNTIME');self.assertIsNone(value['decision']['usage_bytes'])
        self.assertFalse(value['container_created']);self.assertFalse(value['staging_started'])
    def test_fixed_native_probe_uses_empty_pipe_not_devnull_and_retains_bounds(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        port=SimpleNamespace(run_bounded=Mock(return_value=(0,b'[]',b'')),Fault=RuntimeError)
        with patch.object(storage,'_PORT',port):row=storage.fixed_query(['info','--format','json'])
        self.assertEqual(row['exit_code'],0);kwargs=port.run_bounded.call_args.kwargs
        self.assertEqual(kwargs['data'],b'');self.assertEqual(kwargs['timeout'],10)
        self.assertEqual(kwargs['out_cap'],262144);self.assertEqual(kwargs['err_cap'],65536)
    def test_existing_cleanup_boundary_requires_full_creator_incarnation_and_nonce(self):
        cleanup=Path(__file__).with_name('cleanup-runtime.ps1')
        pwsh=Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/native/powershell/pwsh.exe'
        script=r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__PATH__',[ref]$tokens,[ref]$errors)
if(@($errors).Count){throw 'Cleanup parser failure'}
$function=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-CleanupContainerIdentity'},$true)
. ([scriptblock]::Create($function.Extent.Text))
$result=[ordered]@{}
foreach($case in @('valid','foreign_cid','foreign_image','nonce','owner','incarnation','birth','missing_birth','foreign_mount','failed_creator','fake_stdout','foreign_creator_label')){
 $ctx=@{container_id=('a'*64);image=('sha256:'+('b'*64));exclusive_nonce=('c'*32);exclusive_owner='owner';owns_vm=$false;container_created='2026-10-27T10:00:00Z';container_started_at='2026-10-27T10:00:01Z'}
 $creator=@{label='container-start';executable='C:\Program Files\WSL\wslc.exe';exit_code=0;timed_out=$false;output_drained=$true;owned_tree_termination_requested=$false;stdout=$ctx.container_id;args=@('run','--label','aiui.toolkit.owner=owner','--label',('aiui.toolkit.nonce='+('c'*32)))}
 $actual=@{Id=$ctx.container_id;Image=$ctx.image;Created=$ctx.container_created;State=@{StartedAt=$ctx.container_started_at;Running=$false};Config=@{Labels=@{'aiui.toolkit.owner'='owner';'aiui.toolkit.nonce'=('c'*32)}};Mounts=@()}
 switch($case){
 foreign_cid {$actual.Id='d'*64};foreign_image {$actual.Image='sha256:'+('d'*64)}
 nonce {$actual.Config.Labels.'aiui.toolkit.nonce'='d'*32};owner {$actual.Config.Labels.'aiui.toolkit.owner'='other'}
 incarnation {$actual.Created='2026-10-26T00:00:00Z'};birth {$actual.State.StartedAt='2026-10-26T00:00:00Z'}
 missing_birth {$ctx.container_started_at=$null;$actual.State.StartedAt=$null}
 foreign_mount {$actual.Mounts=@(@{Source='foreign-volume'})};failed_creator {$creator.exit_code=1}
 fake_stdout {$creator.stdout='d'*64};foreign_creator_label {$creator.args=@('run','--label','aiui.toolkit.owner=other')}
 }
 try{Assert-CleanupContainerIdentity $ctx $creator $actual;$result[$case]=$true}
 catch{if($_.Exception.Message -cne 'CLEANUP_IDENTITY_NOT_VERIFIED'){throw};$result[$case]=$false}
}
$result|ConvertTo-Json -Compress
'''.replace('__PATH__',str(cleanup).replace("'","''"))
        result=subprocess.run([str(pwsh),'-NoProfile','-Command',script],capture_output=True,text=True,check=True,timeout=10)
        observed=json.loads(result.stdout);self.assertTrue(observed.pop('valid'));self.assertTrue(all(v is False for v in observed.values()))

if __name__=='__main__':unittest.main()
