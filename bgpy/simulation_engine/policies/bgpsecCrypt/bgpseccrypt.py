from typing import TYPE_CHECKING, Any, Optional

from bgpy.shared.exceptions import GaoRexfordError
from bgpy.simulation_engine.policies.rov import ROV

if TYPE_CHECKING:
    from bgpy.as_graphs import AS
    from bgpy.shared.enums import Relationships
    from bgpy.simulation_engine.announcement import Announcement as Ann

import ecdsa
import hashlib

class BGPSecCrypt(ROV):
    """Represents BGPSec with Cryptografic functions and processing

    Since there are no real world implementations,
    we assume a secure path preference of security third,
    which is in line with the majority of users
    for the survey results in "A Survey of Interdomain Routing Policies"
    https://www.cs.bu.edu/~goldbe/papers/survey.pdf

    Also - this adopts from ROV since it's extremely unlikely that an AS
    would deploy BGPSec without first deploying ROV

    Since there are no real templates to the signature process, as mentioned above,
    standard elyptic curve signatures and sha256 hashing are used through ecdsa and hashlib from python
    """

    name = "BGPSecCrypt"

    def seed_ann(self, ann: "Ann") -> None:
        """Seeds announcement at this AS and initializes BGPSec path"""

        # This ann is valid, add the bgpsec as path
        if ann.as_path == (self.as_.asn,):
            ann = ann.copy({"bgpsec_as_path": ann.as_path})
        super().seed_ann(ann)

    @staticmethod
    def bgpsec_valid(ann: "Ann", asn: int) -> bool:
        """Returns whether or not an announcement is valid by BGPSec"""
        return ann.bgpsec_next_asn == asn and ann.bgpsec_as_path == ann.as_path

    def bgpsec_signatures_valid(self, ann: "Ann", asn: int, sendAS: "AS") -> bool:
        """Returns whether or not an announcement is cryptograpically valid by BGPSec"""
        if(ann.as_path == (self.as_.asn,)): ### assumes announcement has as_path length of 1 when just seeded or otherwise more than just own asn in as_path
            return True  ### if only as self is in as_path, then announcement will not have signatures till propagation
        
        if(ann.bgpsec_signatures is None): ### "ann.bgpsec_signatures is not None" for indexing necessary"
            return False 
        
        as_path = ann.as_path
        bgpsec_path = ann.bgpsec_as_path
        signatures = ann.bgpsec_signatures
        
        graph = self.as_.as_graph
        as_list = graph.ases

        assert signatures.__len__ == bgpsec_path.__len__
        for index, asns in enumerate(bgpsec_path):  ### bgpsec_as_path basically replaces SKI object from as path for ease of implementation with missing RPKI
            as_obj = None
            assert as_list is not None
            for obj in as_list: ### enumerate as_graph to get object reference
                if(obj.asn == asns):
                    as_obj = obj
                    break
            if(as_obj is None):
                return False 
            

            assert as_obj.asn in as_path
            prefix = ann.prefix ### stays the same for each signature
            sig = signatures[index] ### signature in index i corresponding to adopting AS with asn x at index i in bgpsec_as_path
            as_pathI = (as_path[index],) + as_path[index:] ###TODO

            if(not as_path[index:]):
                own_hash = self.create_ann_hash(prefix=prefix, next_asn=as_path[index+1]); 
            else:
                signaturesI = signatures[index:]
                
                own_hash = self.create_ann_hash(prefix=prefix, next_asn=as_path[index+1], path=as_pathI, signatures=signaturesI)
            

            if(as_obj.verify_signature(updatehash=own_hash, signature=sig) != True):        ### check signature for adopting as at index in path
                return False
    
        return True


    def _policy_propagate(
        self,
        neighbor: "AS",
        ann: "Ann",
        propagate_to: "Relationships",
        send_rels: set["Relationships"],
    ) -> bool:
        """Sets BGPSec fields when propagating

        If sending to bgpsec, set next_as and keep bgpsec_as_path
        otherwise clear out both fields
        """

        if isinstance(neighbor.policy, BGPSecCrypt):
            next_asn = neighbor.asn
            path = ann.bgpsec_as_path
           
            if isinstance(self.as_.policy, BGPSecCrypt) and self.as_.signing_key is not None:
                sig_list = ann.bgpsec_signatures
                sig = self.create_signature(self.create_ann_hash(ann.prefix, neighbor.asn, ann.as_path, sig_list)) ### creates signature over important attributes
                if(sig_list):
                    sig_list = (sig,) + sig_list
                else:
                    sig_list = (sig,)
            else: 
                sig_list = None

        else:
            next_asn = None
            path = ()
            sig_list = None
        
        send_ann = ann.copy({"bgpsec_next_asn": next_asn, "bgpsec_as_path": path, "bgpsec_signatures": sig_list})
        self._process_outgoing_ann(neighbor, send_ann, propagate_to, send_rels)
        return True

    ### TODO ?
    # Mypy doesn't understand the superclass
    def _copy_and_process(
        self,
        ann: "Ann",
        recv_relationship: "Relationships",
        overwrite_default_kwargs: dict[Any, Any] | None = None,
    ) -> "Ann":
        """Sets the bgpsec_as_path.

        prepends ASN if valid, otherwise clears
        """
        if self.bgpsec_valid( ann, self.as_.asn):
            bgpsec_as_path = (self.as_.asn, *ann.bgpsec_as_path)
        else:
            bgpsec_as_path = ()

        if overwrite_default_kwargs is None:
            overwrite_default_kwargs = {}

        overwrite_default_kwargs["bgpsec_as_path"] = overwrite_default_kwargs.get(
            "bgpsec_as_path", bgpsec_as_path
        )

        return super()._copy_and_process(
            ann, recv_relationship, overwrite_default_kwargs
        )

    def _get_best_ann_by_bgpsec(
        self, current_ann: "Ann", new_ann: "Ann"
    ) -> Optional["Ann"]:
        current_valid = self.bgpsec_valid( current_ann, self.as_.asn)
        new_valid = self.bgpsec_valid( new_ann, self.as_.asn)

        if current_valid and not new_valid:
            return current_ann
        elif not current_valid and new_valid:
            return new_ann
        else:
            return None

    def _get_best_ann_by_gao_rexford(
        self,
        current_ann: Optional["Ann"],
        new_ann: "Ann",
    ) -> "Ann":
        """Determines if the new ann > current ann by Gao Rexford"""

        assert new_ann is not None, "New announcement can't be None"

        if current_ann is None:
            return new_ann
        else:
            # Inspiration for this func refactor came from bgpsecsim
            # for func in self._gao_rexford_funcs:
            #     best_ann = func(current_ann, new_ann)
            #     if best_ann is not None:
            #         assert isinstance(best_ann, Ann), "mypy type check"
            #         return best_ann

            # Having this dynamic like above is literally 7x slower, resulting
            # in bottlenecks. Gotta do it the ugly way unfortunately
            ann = self._get_best_ann_by_local_pref(current_ann, new_ann)
            if ann:
                return ann
            else:
                ann = self._get_best_ann_by_as_path(current_ann, new_ann)
                if ann:
                    return ann
                else:
                    ann = self._get_best_ann_by_bgpsec(current_ann, new_ann)
                    if ann:
                        return ann
                    else:
                        return self._get_best_ann_by_lowest_neighbor_asn_tiebreaker(
                            current_ann, new_ann
                        )
            raise GaoRexfordError("No ann was chosen")




    #################
    # Signing funcs #
    #################

    def get_vk(self) -> ecdsa.keys.VerifyingKey:
        return self.as_.verifying_key

    def create_ann_hash(
        self,
        prefix: str,
        next_asn: int,
        path: tuple[int, ...] | None = None,
        signatures: tuple[bytes, ...] | None = None,
    ) -> bytes:
        if(path is not None):
            sign_path = (next_asn,) + path
        else:
            sign_path = (next_asn, self.as_.asn)

        if(signatures is None):
            seed_tuple = (prefix, sign_path)
            hashed_update = hashlib.sha256(string=str(seed_tuple).encode(), usedforsecurity=True).digest()
        else:
            hash_tuple = (prefix, sign_path, signatures) ### Signing over (Prefix P, AS_Path & Signature list), see Paper https://doi.org/10.1016/j.comcom.2017.03.007
            hashed_update = hashlib.sha256(string=str(hash_tuple).encode(), usedforsecurity=True).digest()
        
        return hashed_update
        
    def create_signature(
        #"""This method returns the signature of a Hash given as input"""
        self,
        hash: bytes,
    ):
        assert isinstance(self.as_, AS) and isinstance(self.as_.policy, BGPSecCrypt) 
        return self.as_.signing_key.sign(hash)
    
    def verify_signature(
        #"""This method returns the signature of a Hash given as input"""
        #"""Currently redundant ? """

        self,
        ### asn: int,
        updatehash: bytes,
        signature: bytes,
    ) -> bool:
        try:
            assert self.as_.verifying_key
            vk = self.as_.verifying_key
            vk.verify(signature, updatehash)
        except ecdsa.keys.BadSignatureError:
            return False
        return True