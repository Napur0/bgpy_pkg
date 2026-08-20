from typing import TYPE_CHECKING, Any

from bgpy.simulation_engine.policies.bgp import BGP
from bgpy.simulation_engine.policies.thesis.bgpsecCrypt import BGPSecCrypt

if TYPE_CHECKING:
    from bgpy.as_graphs import AS
    from bgpy.enums import Relationships
    from bgpy.simulation_engine.announcement import Announcement as Ann

import time


class BGPiSecCryptTransitive(BGPSecCrypt):
    """Represents BGPiSec Transitive attributes"""

    name = "BGP-iSec Crypt Transitive Only"

    # Doesn't change the path preference mechanism so that it's easier to deploy
    # and path preference has no benefit
    # as shown in the bgp-isec paper
    # this also follows their recommendation
    # Suppress this. Just using a mixin rather than some weird OO inheritance
    _get_best_ann_by_gao_rexford = BGP._get_best_ann_by_gao_rexford  # noqa: SLF001

    def _policy_propagate(
        self,
        neighbor: "AS",
        ann: "Ann",
        propagate_to: "Relationships",
        send_rels: set["Relationships"],
    ) -> bool:
        """Sets BGPSec fields when propagating"""
        if(self.as_.signing_key is not None):
            sig_list = ann.bgpsec_signatures
            update_hash = self.create_ann_hash(ann.prefix, neighbor.asn, ann.as_path, sig_list)
            sig = (self.as_.asn, self.create_signature(update_hash)) ### creates signature over important attributes

            if(sig_list):
                sig_list = (sig, *sig_list)
            else:
               sig_list = (sig,)

        send_ann = ann.copy(
            {"bgpsec_next_asn": neighbor.asn, "bgpsec_as_path": ann.bgpsec_as_path, "bgpsec_signatures": sig_list}
        )
        self._process_outgoing_ann(neighbor, send_ann, propagate_to, send_rels)
        return True

    def _copy_and_process(
        self,
        ann: "Ann",
        recv_relationship: "Relationships",
        overwrite_default_kwargs: dict[Any, Any] | None = None,
    ) -> "Ann":
        """Sets the bgpsec_as_path.

        prepends ASN 
        """
        bgpsec_as_path = (self.as_.asn, *ann.bgpsec_as_path)
        bgpsec_signatures = ann.bgpsec_signatures

        if overwrite_default_kwargs is None:
            overwrite_default_kwargs = {}

        overwrite_default_kwargs["bgpsec_as_path"] = overwrite_default_kwargs.get(
            "bgpsec_as_path", bgpsec_as_path
        )
        overwrite_default_kwargs["bgpsec_signatures"] = overwrite_default_kwargs.get(
            "bgpsec_signatures", bgpsec_signatures
        )

        return super()._copy_and_process(
            ann, recv_relationship, overwrite_default_kwargs
        )

    def _valid_ann(self, ann: "Ann", from_rel: "Relationships") -> bool:
        """Determines bgp-isec transitive validity and super() validity"""
        return self._bgpisec_trans_verification(ann, from_rel) and super()._valid_ann(ann, from_rel)

    def _bgpisec_transitive_valid_ann(
        self,
        ann: "Ann",
        from_rel: "Relationships",
    ) -> bool:
        """Determines bgp-isec transitive validity

        If any ASes along the AS path are adopting and are not in the bgpsec_as_path,
        that means those ASes didn't add signatures, therefore the ann is missing
        signatures and should be dropped
        """

        as_graph = self.as_.as_graph
        bgpsec_signatures = ann.bgpsec_as_path
        for asn in ann.as_path:
            if asn not in bgpsec_signatures and isinstance(
                as_graph.as_dict[asn].policy, BGPiSecCryptTransitive
            ):
                return False
        return True

    def _bgpisec_trans_verification(self, ann: "Ann", from_rel: "Relationships"):

        self._verification_counter += 1
        start_time = time.perf_counter_ns()

        standard = self._bgpisec_transitive_valid_ann(ann, from_rel) 
        crypt = self._bgpisec_transitive_crypt_valid_ann(ann, from_rel)

        duration = time.perf_counter_ns() - start_time
        self._verification_process_durations.append(duration)

        return standard and crypt


    def _bgpisec_transitive_crypt_valid_ann(
        self,
        ann: "Ann",
        from_rel: "Relationships",
    ) -> bool:
        """Determines bgp-isec transitive validity

        If any ASes along the AS path are adopting don't have a fitting signature attached,
        that means those ASes didn't add signatures, therefore the ann should be dropped
        """

        as_graph = self.as_.as_graph
        bgpsec_path = ann.bgpsec_as_path

        if(ann.bgpsec_signatures is not None):
            signatures  = list(ann.bgpsec_signatures)
        else:
            signatures = []

        sig_index = 0
        for as_index, asn in enumerate(ann.as_path):
            if(asn == self.as_.asn):
                continue
            as_obj = as_graph.as_dict[asn]

            if isinstance(
                as_obj.policy, BGPiSecCryptTransitive
            ): 
                if(as_index == 0):
                    nas = self.as_.asn
                else:
                    nas = ann.as_path[as_index-1]
            
                if(len(signatures) == 0):
                    return False      
                if(len(signatures) < sig_index+1):
                    return False 


                
                if(len(signatures[sig_index:]) == 1): ## if this is last signature in list
                    own_hash = self.create_ann_hash(prefix=ann.prefix, next_asn=nas, path=ann.as_path[as_index:])
                else:
                    own_hash = self.create_ann_hash(prefix=ann.prefix, next_asn=nas, path=ann.as_path[as_index:], signatures=tuple(signatures[sig_index+1:]))
                if(as_obj.policy.verify_signature(updatehash=own_hash, signature=signatures[sig_index][1])):
                    sig_index = sig_index+1
                    continue
                else:
                    return False
        return True