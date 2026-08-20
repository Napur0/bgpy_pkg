from typing import TYPE_CHECKING, Any, Optional

from bgpy.shared.exceptions import GaoRexfordError
from bgpy.simulation_engine.policies.thesis import BGPSecCrypt

if TYPE_CHECKING:
    from bgpy.as_graphs import AS
    from bgpy.shared.enums import Relationships
    from bgpy.simulation_engine.announcement import Announcement as Ann

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import time


class BGPSecRSA(BGPSecCrypt):
    """Represents BGPSec with Cryptografic functions and processing using RSA process for signatures
    """

    name = "BGPSecRSA"


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

        if isinstance(neighbor.policy, BGPSecRSA):
            next_asn = neighbor.asn
            path = ann.bgpsec_as_path
            if(self.as_.rsa_private_key is not None):
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

    #################
    # Signing funcs #
    #################
        
    def create_signature(
        #"""This method returns the signature of a Hash given as input"""
        self,
        hash: bytes,
    ):
        assert self.as_.rsa_private_key
        signing_starttime = time.perf_counter_ns()
        signature = self.as_.rsa_private_key.sign(hash, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
        self._signing_durations.append(time.perf_counter_ns() - signing_starttime)
        return signature
    
    def verify_signature(        
        self,
        updatehash: bytes,
        signature: bytes,
    ) -> bool:
        """This method returns the signature of a Hash given as input"""

        try:
            assert self.as_.rsa_public_key
            verifying_starttime = time.perf_counter_ns()
            vk = self.as_.rsa_public_key
            vk.verify(signature, updatehash, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
            self._verification_durations.append(time.perf_counter_ns() - verifying_starttime)
        except InvalidSignature:
            return False
        return True