"""Pure Xlib ABI fixtures and mocked SAME-owner ports. No X11/WSL/GUI/GPU.

The measured example is a test vector, never accepted native evidence.
"""
import ctypes as C
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("geometry_wslc_host", Path(__file__).with_name("wslc_host.py"))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
probe = {"__name__":"pure_test_not_main"}
exec(compile(host.X11_GEOMETRY_PROGRAM, "fixed-x11-geometry-program", "exec"), probe)
TAG = "toolkit-wslc-0123456789abcdef01234567"
TITLE = "Makepad [" + TAG + "]"
RAIL_TITLE = TITLE + " (Ubuntu)"
FOCUS_SHA = "9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB"
CLIENT = {"x":156,"y":87,"width":875,"height":600}
FRAME = {"x":118,"y":28,"width":951,"height":697}


class RailIdentityTests(unittest.TestCase):
    def test_guest_title_comes_from_approved_fixture_and_launch_nonce_never_rail(self):
        cfg={"source_commit":host.PIN,"expected_identity":{"executable":"/opt/proof/ai-workspace-fixture","executable_sha256":FOCUS_SHA}}
        self.assertEqual(host.focus_content_title(cfg,TAG),TITLE)
        for rail in (TITLE,RAIL_TITLE):self.assertTrue(host.supported_rail_title(TITLE,rail))
        for rail in (TITLE+" (Other)",RAIL_TITLE+" (Ubuntu)","foreign "+RAIL_TITLE,RAIL_TITLE+" extra"):
            self.assertFalse(host.supported_rail_title(TITLE,rail))
        for changed in ({**cfg,"source_commit":"foreign"},{**cfg,"profile_kind":"ModuleShell"},
            {**cfg,"expected_identity":{**cfg["expected_identity"],"executable_sha256":"A"*64}},
            {**cfg,"expected_identity":{**cfg["expected_identity"],"executable":"/foreign"}}):
            with self.assertRaisesRegex(host.Fault,"WSLC_GEOMETRY_TITLE_PROFILE_UNSUPPORTED"):
                host.focus_content_title(changed,TAG)
        with self.assertRaises(host.Fault):host.focus_content_title(cfg,TAG+" extra")

    def test_owner_hide_changes_state_without_changing_kernel_identity(self):
        launch = {"hwnd":123,"pid":456,"birth":"789","title":TITLE,"visible":True}
        current = {**launch,"visible":False}
        self.assertTrue(host.same_rail_identity(launch,current,TAG))
        self.assertNotEqual(launch,current)
        for name,value in (("hwnd",124),("pid",457),("birth","790"),("title",TITLE+" foreign")):
            with self.subTest(name=name):
                self.assertFalse(host.same_rail_identity(launch,{**current,name:value},TAG))
        self.assertFalse(host.same_rail_identity(launch,{**current,"observation_error":"DENIED"},TAG))


class Function:
    def __init__(self, callback): self.callback = callback
    def __call__(self, *args): return self.callback(*args)


class FakeXlib:
    """Only read operations; memory ownership follows Xlib's output-pointer ABI."""
    def __init__(self):
        self.keep = []
        self.calls = []
        self.atoms = {n:i+100 for i,n in enumerate(("_NET_WM_PID","_NET_WM_NAME","UTF8_STRING","WM_NAME","STRING","CARDINAL","_NET_FRAME_EXTENTS"))}
        self.children = {1:[20],20:[10],10:[]}
        self.rects = {1:{"x":0,"y":0,"width":2000,"height":1200},20:dict(FRAME),10:dict(CLIENT)}
        self.properties = {
            (10,self.atoms["_NET_WM_PID"]):(self.atoms["CARDINAL"],32,[10]),
            (10,self.atoms["_NET_WM_NAME"]):(self.atoms["UTF8_STRING"],8,TITLE.encode()),
            (10,self.atoms["_NET_FRAME_EXTENTS"]):(self.atoms["CARDINAL"],32,[38,38,59,38]),
        }
        self.after_bytes = 0
        self.move_on_second_client_read = False
        self.client_reads = 0
        self.error_on_sync = False
        self.map_state = 2
        self.property_reads = {}
        self.change_pid_after = False
        self.change_title_after = False
        names = {"XOpenDisplay":self.open,"XCloseDisplay":lambda d:0,"XDefaultRootWindow":lambda d:1,
            "XInternAtom":lambda d,n,only:self.atoms[n.decode()],"XGetWindowProperty":self.property,
            "XQueryTree":self.tree,"XGetWindowAttributes":self.attributes,"XTranslateCoordinates":self.translate,
            "XFree":lambda p:0,"XSync":self.sync,"XSetErrorHandler":self.set_handler}
        for name, fn in names.items():
            def recorded(*args, _name=name, _fn=fn):
                self.calls.append(_name);return _fn(*args)
            setattr(self,name,Function(recorded))

    @staticmethod
    def set(ptr, kind, value): C.cast(ptr,C.POINTER(kind))[0] = value

    def open(self, display):
        if display != b":0": raise AssertionError("wrong upstream display")
        return 123

    def set_handler(self, handler): self.handler=handler;return None
    def sync(self, display, discard):
        if self.error_on_sync:self.handler(None,None)
        return 0

    def property(self, d, w, atom, offset, length, delete, requested, actual, fmt, count, after, data):
        if offset!=0 or length!=1024 or delete or requested!=0:raise AssertionError("unbounded/mutating property read")
        value=self.properties.get((w,atom))
        key=(w,atom);self.property_reads[key]=self.property_reads.get(key,0)+1
        if self.change_pid_after and key==(10,self.atoms["_NET_WM_PID"]) and self.property_reads[key]>=3:
            value=(self.atoms["CARDINAL"],32,[999])
        if self.change_title_after and key==(10,self.atoms["_NET_WM_NAME"]) and self.property_reads[key]>=2:
            value=(self.atoms["UTF8_STRING"],8,(TITLE+" changed").encode())
        if value is None:
            self.set(actual,C.c_ulong,0);self.set(fmt,C.c_int,0);self.set(count,C.c_ulong,0)
            self.set(after,C.c_ulong,0);self.set(data,C.c_void_p,None);return 0
        kind,form,payload=value
        storage=C.create_string_buffer(payload) if form==8 else (C.c_ulong*len(payload))(*payload)
        self.keep.append(storage)
        self.set(actual,C.c_ulong,kind);self.set(fmt,C.c_int,form);self.set(count,C.c_ulong,len(payload))
        self.set(after,C.c_ulong,self.after_bytes);self.set(data,C.c_void_p,C.cast(storage,C.c_void_p).value)
        return 0

    def tree(self,d,w,root,parent,children,count):
        more=self.children[w]
        previous=next((p for p,items in self.children.items() if w in items),0)
        self.set(root,C.c_ulong,1);self.set(parent,C.c_ulong,previous);self.set(count,C.c_uint,len(more))
        storage=(C.c_ulong*len(more))(*more);self.keep.append(storage)
        C.cast(children,C.POINTER(C.POINTER(C.c_ulong)))[0]=C.cast(storage,C.POINTER(C.c_ulong))
        return 1

    def attributes(self,d,w,out):
        value=C.cast(out,C.POINTER(probe["Attributes"])).contents
        value.root=1;value.width=self.rects[w]["width"];value.height=self.rects[w]["height"]
        value.border_width=0;value.map_state=self.map_state;value.klass=1
        return 1

    def translate(self,d,w,root,x,y,outx,outy,child):
        if root!=1 or x!=0 or y!=0:raise AssertionError("unexpected coordinate query")
        dx=0
        if w==10:
            self.client_reads+=1
            if self.move_on_second_client_read and self.client_reads>1:dx=1
        self.set(outx,C.c_int,self.rects[w]["x"]+dx);self.set(outy,C.c_int,self.rects[w]["y"])
        self.set(child,C.c_ulong,0)
        return 1


def observe(fake=None, pid=10, title=TITLE):
    fake = fake or FakeXlib()
    with patch.object(C,"CDLL",side_effect=AssertionError("tests must never open native Xlib")):
        return probe["query"](pid,title,lib=fake)


class X11Geometry(unittest.TestCase):
    def test_fixed_program_failure_stdout_contains_stage_without_exception_text(self):
        fake=FakeXlib();fake.move_on_second_client_read=True
        output=io.StringIO()
        with patch.object(C,"CDLL",return_value=fake),patch.object(sys,"argv",["fixed-probe","10",TITLE]),contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as stopped:
                exec(compile(host.X11_GEOMETRY_PROGRAM,"fixed-x11-geometry-program","exec"),{"__name__":"__main__"})
        self.assertEqual(stopped.exception.code,2)
        diagnostic=json.loads(output.getvalue())
        self.assertEqual(diagnostic["error"],"WSLC_X11_GEOMETRY_UNVERIFIED")
        self.assertEqual(diagnostic["stage"],"RECHECK_PID_AND_CLIENT")
        self.assertEqual(diagnostic["owned_candidates"],[{"window":10,"expected_guest_pid":10,"title":TITLE,
            "pid_property":{"type":fake.atoms["CARDINAL"],"format":32,"values":[10]}}])
        self.assertEqual(set(diagnostic),{"error","stage","owned_candidates","pid_matches","exact_matches"})

    def test_failure_stages_are_bounded_and_diagnostics_never_expose_foreign_titles(self):
        fake=FakeXlib()
        fake.properties[(10,fake.atoms["_NET_WM_NAME"])]=(fake.atoms["UTF8_STRING"],8,b"unrelated desktop title")
        with self.assertRaises(ValueError):observe(fake)
        diagnostic=probe["failure_diagnostic"]()
        self.assertEqual(diagnostic["stage"],"UNIQUE_EXACT_TITLE")
        self.assertEqual(diagnostic["pid_matches"],0);self.assertEqual(diagnostic["exact_matches"],0)
        self.assertEqual(diagnostic["owned_candidates"],[])
        self.assertNotIn("unrelated",json.dumps(diagnostic))
        fake=FakeXlib();fake.properties[(10,fake.atoms["_NET_WM_NAME"])]=(fake.atoms["UTF8_STRING"],8,RAIL_TITLE.encode())
        with self.assertRaises(ValueError):observe(fake)
        self.assertEqual(probe["failure_diagnostic"]()["owned_candidates"],[{"window":10,"expected_guest_pid":10,"title":RAIL_TITLE,
            "pid_property":{"type":fake.atoms["CARDINAL"],"format":32,"values":[10]}}])
        fake=FakeXlib();fake.move_on_second_client_read=True
        with self.assertRaises(ValueError):observe(fake)
        self.assertEqual(probe["failure_diagnostic"]()["stage"],"RECHECK_PID_AND_CLIENT")
        fake=FakeXlib();fake.properties[(10,fake.atoms["_NET_FRAME_EXTENTS"])]=(fake.atoms["CARDINAL"],32,[39,38,59,38])
        with self.assertRaises(ValueError):observe(fake)
        self.assertEqual(probe["failure_diagnostic"]()["stage"],"FRAME_CONTENT_AGREEMENT")

    def test_actual_property_and_reparent_observations_agree(self):
        fake=FakeXlib();result=observe(fake)
        self.assertEqual(result["client"],CLIENT)
        self.assertEqual(result["frame"],FRAME)
        self.assertEqual(result["frame_extents"],[38,38,59,38])
        self.assertEqual(result["frame_window"],20)
        self.assertEqual(result["pid_property"],10);self.assertEqual(result["expected_guest_pid"],10)
        self.assertEqual(result["identity_source"],"NET_WM_PID_AND_UNIQUE_TITLE");self.assertNotIn("pid",result)
        self.assertTrue(all(name.startswith(("XGet","XQuery","XTranslate","XOpen","XClose","XDefault","XIntern","XFree","XSync","XSetError")) for name in fake.calls))

    def test_absent_pid_is_explicit_launch_title_association_not_an_observed_pid(self):
        fake=FakeXlib();del fake.properties[(10,fake.atoms["_NET_WM_PID"])]
        result=observe(fake)
        self.assertIsNone(result["pid_property"]);self.assertEqual(result["expected_guest_pid"],10)
        self.assertEqual(result["identity_source"],"APPROVED_LAUNCH_NONCE_AND_UNIQUE_TITLE")
        self.assertNotIn("pid",result);self.assertEqual(result["client"],CLIENT)

    def test_present_wrong_or_malformed_pid_never_uses_absence_path(self):
        for kind,form,payload in [("CARDINAL",32,[999]),("STRING",32,[10]),("CARDINAL",32,[]),
            ("CARDINAL",32,[10,10]),("CARDINAL",8,b"10"),("CARDINAL",32,[2**32-1])]:
            fake=FakeXlib();fake.properties[(10,fake.atoms["_NET_WM_PID"])]=(fake.atoms[kind],form,payload)
            with self.subTest(kind=kind,form=form,payload=payload),self.assertRaises(ValueError):observe(fake)

    def test_duplicate_exact_title_refuses_even_with_missing_or_foreign_pid(self):
        for pid_value in (None,999,10):
            fake=FakeXlib();fake.children[1].append(30);fake.children[30]=[];fake.rects[30]=dict(CLIENT)
            fake.properties[(30,fake.atoms["_NET_WM_NAME"])]=(fake.atoms["UTF8_STRING"],8,TITLE.encode())
            if pid_value is not None:fake.properties[(30,fake.atoms["_NET_WM_PID"])]=(fake.atoms["CARDINAL"],32,[pid_value])
            with self.subTest(pid=pid_value),self.assertRaises(ValueError):observe(fake)
            self.assertEqual(probe["failure_diagnostic"]()["exact_matches"],2)

    def test_pid_property_and_title_must_remain_exact_before_and_after(self):
        for attr in ("change_pid_after","change_title_after"):
            fake=FakeXlib();setattr(fake,attr,True)
            with self.subTest(attr=attr),self.assertRaises(ValueError):observe(fake)

    def test_property_without_reparent_is_observed_not_guessed(self):
        fake=FakeXlib();fake.children={1:[10],10:[]}
        self.assertEqual(observe(fake)["frame"],FRAME)
        self.assertIsNone(observe(fake)["frame_window"])

    def test_hidden_geometry_does_not_invent_visibility_or_key_focus(self):
        for state in (0,1,2):
            fake=FakeXlib();fake.map_state=state;result=observe(fake)
            self.assertEqual(result["client"],CLIENT)
            self.assertNotIn("focused",result);self.assertNotIn("visible",result)
        fake=FakeXlib();fake.map_state=3
        with self.assertRaises(ValueError):observe(fake)

    def test_missing_property_uses_only_exact_real_reparent(self):
        fake=FakeXlib();del fake.properties[(10,fake.atoms["_NET_FRAME_EXTENTS"])]
        result=observe(fake)
        self.assertEqual(result["frame_source"],"REPARENT_FRAME")
        self.assertEqual(result["frame_extents"],[38,38,59,38])
        fake.children={1:[10],10:[]}
        with self.assertRaises(ValueError):observe(fake)

    def test_unique_pid_and_full_title_both_required(self):
        for pid,title in [(11,TITLE),(10,TAG),(10,TITLE+" changed")]:
            with self.subTest(pid=pid,title=title),self.assertRaises(ValueError):observe(pid=pid,title=title)
        fake=FakeXlib();fake.children[1].append(30);fake.children[30]=[];fake.rects[30]=dict(CLIENT)
        for atom in ("_NET_WM_PID","_NET_WM_NAME"):
            fake.properties[(30,fake.atoms[atom])]=fake.properties[(10,fake.atoms[atom])]
        with self.assertRaises(ValueError):observe(fake)

    def test_contradictory_or_malformed_properties_never_fall_back(self):
        for extents in ([39,38,59,38],[-1,38,59,38],[38,38,59],[38,38,59,99999]):
            fake=FakeXlib();fake.properties[(10,fake.atoms["_NET_FRAME_EXTENTS"])]=(fake.atoms["CARDINAL"],32,extents)
            with self.subTest(extents=extents),self.assertRaises(ValueError):observe(fake)

    def test_truncated_properties_async_errors_and_moving_window_refuse(self):
        for key in ("after_bytes","error_on_sync","move_on_second_client_read"):
            fake=FakeXlib();setattr(fake,key,1)
            with self.subTest(key=key),self.assertRaises(ValueError):observe(fake)

    def test_tree_bound_and_cycles_refuse(self):
        fake=FakeXlib();fake.children[1]=list(range(100,4197))
        with self.assertRaises(ValueError):observe(fake)
        fake=FakeXlib();fake.children[10]=[20]
        with self.assertRaises(ValueError):observe(fake)

    def test_client_must_be_inside_measured_frame(self):
        fake=FakeXlib();del fake.properties[(10,fake.atoms["_NET_FRAME_EXTENTS"])]
        fake.rects[20]["x"]=157
        with self.assertRaises(ValueError):observe(fake)


class ExistingOwnerGeometry(unittest.TestCase):
    def owner(self):
        obj=host.Owner.__new__(host.Owner)
        obj.cfg={"session_id":"synthetic-session","generation":7,"source_commit":host.PIN,
            "expected_identity":{"executable":"/opt/proof/ai-workspace-fixture","executable_sha256":FOCUS_SHA}}
        obj.pid=10;obj.tag=TAG;obj.geometry_index=0
        obj.rail={"hwnd":55,"pid":66,"birth":"77","title":RAIL_TITLE,"visible":False}
        actual={"container_id":"a"*64,"process_start_ticks":"88","rail_hwnd":55,"rail_pid":66,"rail_process_birth":"77","rail_visible":False}
        obj.validate=Mock(return_value=actual);obj.save=Mock();obj.budget=lambda seconds:min(seconds,6)
        return obj,actual

    def test_fixed_upstream_query_is_bounded_source_bound_and_original_output_saved(self):
        obj,actual=self.owner();raw=json.dumps(observe()).encode()+b"\n"
        native={"native_client":dict(FRAME),"native_outer":dict(FRAME)}
        with patch.object(host,"rail_windows",return_value=[obj.rail]),patch.object(host,"rail_geometry",return_value=native),patch.object(host,"run_bounded",return_value=(0,raw,b"")) as run:
            result=obj.host_content_geometry(actual)
        argv=run.call_args.args[0]
        self.assertEqual(argv[:5],[r"C:\Windows\System32\wsl.exe","-d","Ubuntu","--","timeout"])
        self.assertEqual(argv[-4:],["-c",host.X11_GEOMETRY_PROGRAM,"10",TITLE])
        self.assertIn("/usr/bin/python3",argv);self.assertLessEqual(run.call_args.kwargs["timeout"],6)
        self.assertEqual(run.call_args.kwargs["out_cap"],host.INPUT_CAP)
        witness=result["geometry"]
        self.assertEqual(witness["title"],TITLE);self.assertEqual(witness["x11"]["title"],TITLE)
        self.assertEqual(witness["rail_title"],RAIL_TITLE)
        self.assertNotEqual(witness["title"],witness["rail_title"])
        self.assertEqual(obj.save.call_args_list[0].args[1]["title"],TITLE)
        self.assertEqual(obj.save.call_args_list[0].args[1]["rail_title"],RAIL_TITLE)
        self.assertEqual(witness["raw_x11_utf8"].encode(),raw)
        self.assertEqual(witness["raw_x11_sha256"],hashlib.sha256(raw).hexdigest().upper())
        self.assertEqual(witness["generation"],7);self.assertEqual(witness["sequence"],1)
        self.assertEqual(obj.validate.call_count,1)
        self.assertEqual(obj.save.call_args_list[0].args[0],"x11-geometry-raw-0001.json")
        self.assertEqual(obj.save.call_args_list[1].args[0],"host-content-geometry-0001.json")

    def test_query_failure_saves_original_but_cannot_publish_geometry(self):
        obj,actual=self.owner()
        with patch.object(host,"rail_windows",return_value=[obj.rail]),patch.object(host,"rail_geometry",return_value={}),patch.object(host,"run_bounded",return_value=(2,b'{"error":"no geometry"}',b"")):
            with self.assertRaisesRegex(host.Fault,"WSLC_X11_GEOMETRY_UNVERIFIED"):obj.host_content_geometry(actual)
        self.assertEqual(obj.save.call_count,1)

    def test_unknown_rail_projection_refuses_before_query_and_drift_after_query_refuses(self):
        obj,actual=self.owner();obj.rail["title"]=TITLE+" (Other)"
        with patch.object(host,"rail_windows",return_value=[obj.rail]),patch.object(host,"run_bounded") as run:
            with self.assertRaisesRegex(host.Fault,"WSLC_RAIL_GEOMETRY_TITLE_INVALID"):obj.host_content_geometry(actual)
        run.assert_not_called()
        obj,actual=self.owner();native={"native_client":dict(FRAME),"native_outer":dict(FRAME)}
        with patch.object(host,"rail_windows",side_effect=[[obj.rail],[{**obj.rail,"title":TITLE}]]),patch.object(host,"rail_geometry",return_value=native),patch.object(host,"run_bounded",return_value=(0,json.dumps(observe()).encode(),b"")):
            with self.assertRaisesRegex(host.Fault,"WSLC_RAIL_GEOMETRY_CHANGED"):obj.host_content_geometry(actual)
        self.assertEqual(obj.save.call_count,1)

    def test_rail_title_cannot_be_reported_as_actual_x11_title(self):
        obj,actual=self.owner();native={"native_client":dict(FRAME),"native_outer":dict(FRAME)}
        wrong=observe();wrong["title"]=RAIL_TITLE
        with patch.object(host,"rail_windows",return_value=[obj.rail]),patch.object(host,"rail_geometry",return_value=native),patch.object(host,"run_bounded",return_value=(0,json.dumps(wrong).encode(),b"")):
            with self.assertRaisesRegex(host.Fault,"WSLC_X11_GEOMETRY_IDENTITY_INVALID"):obj.host_content_geometry(actual)
        self.assertEqual(obj.save.call_count,1)

    def test_owner_requires_explicit_honest_nullable_pid_fields_and_current_guest_identity(self):
        fake=FakeXlib();del fake.properties[(10,fake.atoms["_NET_WM_PID"])]
        original=observe(fake)
        for change in (lambda v:v.pop("pid_property"),lambda v:v.update(pid=10),
            lambda v:v.update(expected_guest_pid=999),lambda v:v.update(identity_source="NET_WM_PID_AND_UNIQUE_TITLE"),
            lambda v:v.update(pid_property=999)):
            obj,actual=self.owner();native={"native_client":dict(FRAME),"native_outer":dict(FRAME)}
            value=dict(original);change(value)
            with patch.object(host,"rail_windows",return_value=[obj.rail]),patch.object(host,"rail_geometry",return_value=native),patch.object(host,"run_bounded",return_value=(0,json.dumps(value).encode(),b"")):
                with self.assertRaisesRegex(host.Fault,"WSLC_X11_GEOMETRY_IDENTITY_INVALID"):obj.host_content_geometry(actual)
            self.assertEqual(obj.save.call_count,1)
        obj,actual=self.owner();native={"native_client":dict(FRAME),"native_outer":dict(FRAME)}
        with patch.object(host,"rail_windows",return_value=[obj.rail]),patch.object(host,"rail_geometry",return_value=native),patch.object(host,"run_bounded",return_value=(0,json.dumps(original).encode(),b"")):
            value=obj.host_content_geometry(actual)["geometry"]
        self.assertIsNone(value["x11"]["pid_property"])
        self.assertEqual(value["x11"]["identity_source"],"APPROVED_LAUNCH_NONCE_AND_UNIQUE_TITLE")
        self.assertEqual(obj.validate.call_count,1)  # call() already validates before entering this method.

    def test_owner_hide_keeps_exact_rail_identity_and_validates_current_visibility(self):
        obj,actual=self.owner();obj.rail["visible"]=True
        current={**obj.rail,"visible":False};native={"native_client":dict(FRAME),"native_outer":dict(FRAME)}
        with patch.object(host,"rail_windows",return_value=[current]),patch.object(host,"rail_geometry",return_value=native),patch.object(host,"run_bounded",return_value=(0,json.dumps(observe()).encode(),b"")):
            result=obj.host_content_geometry(actual)
        self.assertEqual(result["geometry"]["rail_hwnd"],55)
        self.assertTrue(obj.rail["visible"])
        obj,actual=self.owner()
        with patch.object(host,"rail_windows",return_value=[{**obj.rail,"visible":True}]):
            with self.assertRaisesRegex(host.Fault,"WSLC_RAIL_GEOMETRY_IDENTITY_CHANGED"):
                obj.host_content_geometry(actual)

    def test_expiring_owner_cannot_disable_or_extend_the_upstream_deadline(self):
        obj,actual=self.owner();obj.budget=lambda seconds:0.001
        with patch.object(host,"rail_windows",return_value=[obj.rail]),patch.object(host,"rail_geometry",return_value={}),patch.object(host,"run_bounded") as run:
            with self.assertRaisesRegex(host.Fault,"WSLC_OWNER_LIFETIME_EXPIRED"):obj.host_content_geometry(actual)
        run.assert_not_called();obj.save.assert_not_called()

    def test_identity_or_native_rectangle_change_after_query_refuses(self):
        for identity_changed in (False,True):
            obj,actual=self.owner();native={"native_client":dict(FRAME),"native_outer":dict(FRAME)}
            if identity_changed:obj.validate.return_value={**actual,"process_start_ticks":"new"}
            rectangles=[native,{"native_client":dict(CLIENT),"native_outer":dict(FRAME)}] if not identity_changed else [native]
            with patch.object(host,"rail_windows",return_value=[obj.rail]),patch.object(host,"rail_geometry",side_effect=rectangles),patch.object(host,"run_bounded",return_value=(0,json.dumps(observe()).encode(),b"")):
                with self.assertRaises(host.Fault):obj.host_content_geometry(actual)
            self.assertEqual(obj.save.call_count,1)

    def test_internal_packet_has_no_program_display_pid_or_title_argument(self):
        packet={"version":1,"sequence":1,"operation":"host_content_geometry","arguments":{}}
        self.assertEqual(host.packet(json.dumps(packet).encode(),0)["arguments"],{})
        for key in ("program","display","pid","title","command","timeout"):
            packet["arguments"]={key:"untrusted"}
            with self.subTest(key=key),self.assertRaises(host.Fault):host.packet(json.dumps(packet).encode(),0)


if __name__ == "__main__": unittest.main()
