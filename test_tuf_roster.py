#!/usr/bin/env python3
from __future__ import annotations
import base64, copy, hashlib, tempfile, unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
import tuf_roster as tr

class TufRosterTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.private={k:ed25519.Ed25519PrivateKey.generate() for k in ('custodian-a',)}
        self.keys={k:{'keytype':'ed25519','scheme':'ed25519','keyval':{'public':base64.b64encode(v.public_key().public_bytes_raw()).decode()}} for k,v in self.private.items()}
        self.roster={'schema_version':1,'initiative_id':'PGK-FAILCLOSED-001','candidate_generation':'v35','threshold':2,'authorities':[{'key_id':'authority-a','spki_sha256':'1'*64,'custodian_id':'authority-custodian-a'},{'key_id':'authority-b','spki_sha256':'2'*64,'custodian_id':'authority-custodian-b'}]}
        self.write('roster.json',self.roster)
        roster_raw=tr.canonical(self.roster)
        self.targets_signed={'_type':'targets','expires':'2030-01-01T00:00:00Z','spec_version':'1.0.31','targets':{'authority-roster.json':{'hashes':{'sha256':hashlib.sha256(roster_raw).hexdigest()},'length':len(roster_raw)}},'version':1}
        self.root_signed={'_type':'root','expires':'2030-01-01T00:00:00Z','keys':self.keys,'roles':{'root':{'keyids':['custodian-a'],'threshold':1},'targets':{'keyids':['custodian-a'],'threshold':1}},'spec_version':'1.0.31','version':1}
        self.emit()
    def tearDown(self): self.tmp.cleanup()
    def write(self,name,value): (self.root/name).write_bytes(tr.canonical(value))
    def sign(self,signed,keyids):
        raw=tr.canonical(signed)
        return {'signatures':[{'keyid':k,'sig':base64.b64encode(self.private[k].sign(raw)).decode()} for k in keyids],'signed':signed}
    def emit(self,root_keys=('custodian-a',),target_keys=('custodian-a',)):
        self.write('root.json',self.sign(self.root_signed,root_keys)); self.write('targets.json',self.sign(self.targets_signed,target_keys))
        self.digest=hashlib.sha256((self.root/'root.json').read_bytes()).hexdigest()
    def verify(self): return tr.verify_roster(root_path=self.root/'root.json',targets_path=self.root/'targets.json',roster_path=self.root/'roster.json',trusted_root_sha256=self.digest,trusted_targets_sha256=hashlib.sha256((self.root/'targets.json').read_bytes()).hexdigest())
    def test_one_of_one_accepts(self):
        result=self.verify(); self.assertTrue(result['verified']); self.assertEqual(result['threshold'],2); self.assertEqual(result['custodian_count'],2)
    def test_unprovisioned_fails_closed(self):
        with self.assertRaisesRegex(ValueError,'not provisioned'): tr.verify_roster(root_path=self.root/'root.json',targets_path=self.root/'targets.json',roster_path=self.root/'roster.json')
    def test_missing_root_signature_rejected(self):
        self.emit(root_keys=())
        with self.assertRaisesRegex(ValueError,'threshold'): self.verify()
    def test_missing_targets_signature_rejected(self):
        self.emit(target_keys=())
        with self.assertRaisesRegex(ValueError,'threshold'): self.verify()
    def test_two_key_root_policy_rejected(self):
        other=ed25519.Ed25519PrivateKey.generate()
        self.private['custodian-b']=other
        self.keys['custodian-b']={'keytype':'ed25519','scheme':'ed25519','keyval':{'public':base64.b64encode(other.public_key().public_bytes_raw()).decode()}}
        self.root_signed['keys']=self.keys
        self.root_signed['roles']['root']={'keyids':['custodian-a','custodian-b'],'threshold':1}
        self.emit(root_keys=('custodian-a',))
        with self.assertRaisesRegex(ValueError,'exact 1-of-1'): self.verify()
    def test_string_role_keyids_rejected(self):
        self.private['a']=self.private.pop('custodian-a')
        self.keys={'a':self.keys.pop('custodian-a')}
        self.root_signed['keys']=self.keys
        self.root_signed['roles']['root']={'keyids':'a','threshold':1}
        self.root_signed['roles']['targets']={'keyids':'a','threshold':1}
        self.emit(root_keys=('a',),target_keys=('a',))
        with self.assertRaisesRegex(ValueError,'exact 1-of-1'): self.verify()
    def test_boolean_role_threshold_rejected(self):
        self.root_signed['roles']['root']['threshold']=True
        self.emit()
        with self.assertRaisesRegex(ValueError,'exact 1-of-1'): self.verify()
    def test_non_string_role_keyid_rejected_as_value_error(self):
        self.root_signed['roles']['root']['keyids']=[None]
        self.emit()
        with self.assertRaisesRegex(ValueError,'exact 1-of-1'): self.verify()
    def test_non_object_keyval_rejected_as_value_error(self):
        self.root_signed['keys']['custodian-a']['keyval']='not-an-object'
        self.emit()
        with self.assertRaisesRegex(ValueError,'TUF key'): self.verify()
    def test_unused_extra_root_key_rejected(self):
        other=ed25519.Ed25519PrivateKey.generate()
        self.private['custodian-b']=other
        self.keys['custodian-b']={'keytype':'ed25519','scheme':'ed25519','keyval':{'public':base64.b64encode(other.public_key().public_bytes_raw()).decode()}}
        self.root_signed['keys']=self.keys
        self.emit(root_keys=('custodian-a',))
        with self.assertRaisesRegex(ValueError,'exactly the sole custodian key'): self.verify()
    def test_different_single_keys_for_root_and_targets_rejected(self):
        other=ed25519.Ed25519PrivateKey.generate()
        self.private['custodian-b']=other
        self.keys['custodian-b']={'keytype':'ed25519','scheme':'ed25519','keyval':{'public':base64.b64encode(other.public_key().public_bytes_raw()).decode()}}
        self.root_signed['keys']=self.keys
        self.root_signed['roles']['targets']={'keyids':['custodian-b'],'threshold':1}
        self.emit(root_keys=('custodian-a',),target_keys=('custodian-b',))
        with self.assertRaisesRegex(ValueError,'same sole custodian key'): self.verify()
    def test_one_authority_roster_rejected_even_with_single_publisher(self):
        bad=copy.deepcopy(self.roster); bad['threshold']=1; bad['authorities']=bad['authorities'][:1]
        raw=tr.canonical(bad); self.write('roster.json',bad)
        self.targets_signed['targets']['authority-roster.json']={'hashes':{'sha256':hashlib.sha256(raw).hexdigest()},'length':len(raw)}; self.emit()
        with self.assertRaisesRegex(ValueError,'roster scope'): self.verify()
    def test_recomputed_replacement_root_rejected_by_pin(self):
        old=self.digest; self.root_signed['version']=2; self.emit()
        with self.assertRaisesRegex(ValueError,'not trusted'): tr.verify_roster(root_path=self.root/'root.json',targets_path=self.root/'targets.json',roster_path=self.root/'roster.json',trusted_root_sha256=old,trusted_targets_sha256=hashlib.sha256((self.root/'targets.json').read_bytes()).hexdigest())
    def test_replayed_targets_rejected_by_pin(self):
        old=hashlib.sha256((self.root/'targets.json').read_bytes()).hexdigest()
        self.targets_signed['version']=2; self.emit()
        with self.assertRaisesRegex(ValueError,'targets are not trusted'): tr.verify_roster(root_path=self.root/'root.json',targets_path=self.root/'targets.json',roster_path=self.root/'roster.json',trusted_root_sha256=self.digest,trusted_targets_sha256=old)
    def test_expired_targets_rejected(self):
        self.targets_signed['expires']='2020-01-01T00:00:00Z'; self.emit()
        with self.assertRaisesRegex(ValueError,'expired'): self.verify()
    def test_changed_roster_rejected(self):
        changed=copy.deepcopy(self.roster); changed['authorities'][0]['spki_sha256']='a'*64; self.write('roster.json',changed)
        with self.assertRaisesRegex(ValueError,'target mismatch'): self.verify()
    def test_same_authority_custodian_rejected(self):
        bad=copy.deepcopy(self.roster); bad['authorities'][1]['custodian_id']='authority-custodian-a'; raw=tr.canonical(bad); self.write('roster.json',bad)
        self.targets_signed['targets']['authority-roster.json']={'hashes':{'sha256':hashlib.sha256(raw).hexdigest()},'length':len(raw)}; self.emit()
        with self.assertRaisesRegex(ValueError,'distinct authority custodians'): self.verify()
if __name__=='__main__': unittest.main()
