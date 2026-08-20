from typing import TYPE_CHECKING, Any, Optional

from bgpy.shared.exceptions import GaoRexfordError
from bgpy.simulation_engine.policies.rov import ROV

if TYPE_CHECKING:
    from bgpy.as_graphs import AS
    from bgpy.shared.enums import Relationships
    from bgpy.simulation_engine.announcement import Announcement as Ann
    from bgpy.shared.enums import SpecialPercentAdoptions
    from bgpy.simulation_framework import Scenario


import hashlib ### still using hashlib since i started with this and only changed it later to also implement RSA for comparison and changing it would just be additional work
import time
from operator import itemgetter

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from bgpy.thesis.graph_data_aggregator_time import GraphDataAggregatorTime


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
    def __init__(
        self,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        ### For variables for time measuring 
        self._verification_counter = 0
        self._verification_durations: list[int] = []
        self._verification_process_durations: list[int] = []
        self._signing_durations: list[int] = []

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

    def bgpsec_signatures_valid(self, ann: "Ann", asn: int) -> bool:
        """Returns whether or not an announcement is cryptograpically valid by BGPSec"""

        if(ann.as_path == (asn,)): ### assumes announcement has as_path length of 1 when just seeded or otherwise more than just own asn in as_path
            return True  ### if only as self is in as_path, then announcement will not have signatures till propagation
        
        if(ann.bgpsec_signatures is None): ### since its not the first AS for the Ann here, no sigantures means not valid
            return False 

        as_path = ann.as_path
        if(as_path[0]==self.as_.asn):   
            as_path = as_path[1:]
        signatures = ann.bgpsec_signatures

        """
        if(len(as_path) != len(signatures)): ### if AS_PATH is not same length as Signature List then at least 1 AS didnt sign / is non adopting => Announcement is not BGPsec Valid; Same as in simpler bgpsec_valid() func above
            return False
        """
        
        graph = self.as_.as_graph

        prefix = ann.prefix ### stays the same for each signature
        
        for index, sig in enumerate(signatures): 
            
            as_obj = graph.as_dict[as_path[index]]
            
            ##########################
            # Signature Verification #
            ##########################
            assert as_obj.asn in as_path ### should never error, but cleaner to check anyways
            
            ### Length checking, since None is wanted instead of an empty tuple ()
            if (len(as_path[index:]) > 0):
                as_pathI = as_path[index:]
            else:
                as_pathI = None
            if (len(signatures[index:]) > 1):
                signaturesI = signatures[index+1:]
            else:
                signaturesI = None


            if(index == 0):
                next_asn=self.as_.asn
            else:
                next_asn=as_path[index-1]
            own_hash = self.create_ann_hash(prefix=prefix, next_asn=next_asn, path=as_pathI, signatures=signaturesI)
            
            verification = as_obj.policy.verify_signature(updatehash=own_hash, signature=sig[1])
            if(verification != True):        ### check signature for adopting as at index in path
                return False
        return True

    def _bgpsec_verification(
        self, 
        ann: "Ann", 
        asn: int, 
    ) -> bool:
        """ Wrapper Function for new cryptographic Signature functionality and measuring possibilities """

        self._verification_counter += 1
        start_time = time.perf_counter_ns()

        standard = self.bgpsec_signatures_valid(ann, asn) 
        crypt = self.bgpsec_valid(ann, asn)

        duration = time.perf_counter_ns() - start_time
        self._verification_process_durations.append(duration)
    
        return standard and crypt

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
            if(self.as_.signing_key is not None):
                sig_list = ann.bgpsec_signatures
                sig = (self.as_.asn, self.create_signature(self.create_ann_hash(ann.prefix, neighbor.asn, ann.as_path, sig_list))) ### creates signature over important attributes
                if(sig_list):
                    sig_list = (sig, *sig_list)
                else:
                   sig_list = (sig,)
        else:
            next_asn = None
            path = ()
            sig_list = None
        
        send_ann = ann.copy({"bgpsec_next_asn": next_asn, "bgpsec_as_path": path, "bgpsec_signatures": sig_list})
        self._process_outgoing_ann(neighbor, send_ann, propagate_to, send_rels)
        return True

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

        if overwrite_default_kwargs is None:
            overwrite_default_kwargs = {}
        ### small change to structure to not double check signatures on inheriting classes if not necessary
        if (overwrite_default_kwargs.get("bgpsec_as_path", None) is None 
        or overwrite_default_kwargs.get("bgpsec_signatures", None) is None):

            if (self._bgpsec_verification(ann, self.as_.asn)):
                bgpsec_as_path = (self.as_.asn, *ann.bgpsec_as_path)
                bgpsec_signatures = ann.bgpsec_signatures
            else:
                bgpsec_as_path = ()
                bgpsec_signatures = None

            overwrite_default_kwargs["bgpsec_as_path"] = bgpsec_as_path
            overwrite_default_kwargs["bgpsec_signatures"] = bgpsec_signatures

        return super()._copy_and_process(
            ann, recv_relationship, overwrite_default_kwargs
        )

    def _get_best_ann_by_bgpsec(
        self, current_ann: "Ann", new_ann: "Ann"
    ) -> Optional["Ann"]:
        current_valid = self._bgpsec_verification(current_ann, self.as_.asn) 
        new_valid = self._bgpsec_verification(new_ann, self.as_.asn)

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

    def create_ann_hash(
        self,
        prefix: str,
        next_asn: int,
        path: tuple[int, ...] | None = None,
        signatures: tuple[tuple[int, bytes], ...] | None = None, ### int (asn of signing as) only gets added bc its easier to debug. Can be subject to change TODO: Remove
    ) -> bytes:
        if(path is not None):
            sign_path = (next_asn,) + path
        else:
            sign_path = (next_asn, self.as_.asn)

        if(signatures is None):
            seed_tuple = (prefix, sign_path)
            hashed_update = hashlib.sha256(string=str(seed_tuple).encode(), usedforsecurity=True).digest()
        else:
            sigs = tuple(map(itemgetter(1), signatures))
            hash_tuple = (prefix, sign_path, sigs) ### Signing over (Prefix P, AS_Path & Signature list), see Paper https://doi.org/10.1016/j.comcom.2017.03.007
            hashed_update = hashlib.sha256(string=str(hash_tuple).encode(), usedforsecurity=True).digest()
        return hashed_update
        
    def create_signature(
        self,
        hash: bytes,
    ):
        """This method returns the signature of a Hash given as input"""
        assert self.as_.signing_key
        signing_starttime = time.perf_counter_ns()
        signature = self.as_.signing_key.sign(hash, ec.ECDSA(Prehashed(hashes.SHA256())))
        self._signing_durations.append(time.perf_counter_ns() - signing_starttime)
        return signature
    
    def verify_signature(        
        self,
        updatehash: bytes,
        signature: bytes,
    ) -> bool:
        """This method returns the signature of a Hash given as input"""
        try:
            assert self.as_.verifying_key
            verifying_starttime = time.perf_counter_ns()
            vk = self.as_.verifying_key
            vk.verify(signature, updatehash, ec.ECDSA(Prehashed(hashes.SHA256())))
            self._verification_durations.append(time.perf_counter_ns() - verifying_starttime)
        except InvalidSignature:
            return False
        return True



    ###############################
    # Funcs changed for measuring #
    ###############################

    def process_incoming_anns(
        self,
        *,
        from_rel: "Relationships",
        propagation_round: int,
        scenario: "Scenario",
        reset_q: bool = True,
    ) -> None:
        """Process all announcements that were incoming from a specific rel"""
        verification_counts_this_round: list[int] = []

        # For each prefix, get all anns recieved
        for prefix, ann_list in self.recv_q.items():
            # Get announcement currently in local rib
            current_ann: Ann | None = self.local_rib.get(prefix)
            og_ann = current_ann

            self._verification_counter = 0

            # For each announcement that was incoming
            for new_ann in ann_list:
                current_ann = self._get_new_best_ann(current_ann, new_ann, from_rel)

            # This is a new best ann. Process it and add it to the local rib
            if og_ann != current_ann:
                assert current_ann, "mypy type check"
                assert current_ann.seed_asn in (None, self.as_.asn), "Seed ASN is wrong"
                # Save to local rib
                self.local_rib.add_ann(current_ann)

            verification_counts_this_round.append(self._verification_counter)

        self._reset_q(reset_q)

        if verification_counts_this_round:
            GraphDataAggregatorTime.log_verification_counts(
                policy_name= self.as_.policy.name, 
                adoption_rate=scenario.percent_adoption,
                propagation_round=propagation_round,
                verification_counts=verification_counts_this_round,
            )

        self._log_and_reset_timings(self.as_.policy.name, scenario.percent_adoption, propagation_round)



    ### its honestly unfortunatly pretty slow doing saving measurements this way so this could probably use some improvements
    def _log_and_reset_timings(
        self,
        policy_name: str,
        adoption_rate: "float | SpecialPercentAdoptions",
        propagation_round: int,
    ) -> None:
        metrics = [
            ("verification", self._verification_durations),
            ("signing", self._signing_durations),
            ("verification_process", self._verification_process_durations),
        ]

        for data_type, durations in metrics:
            
            if durations:
                GraphDataAggregatorTime.log_time_duration(
                    policy_name=policy_name,
                    adoption_rate=adoption_rate,
                    propagation_round=propagation_round,
                    time_durations=durations,
                    data_type=data_type,
                )

        # Reset for next Round
        self._verification_durations = []
        self._signing_durations = []
        self._verification_process_durations = []

