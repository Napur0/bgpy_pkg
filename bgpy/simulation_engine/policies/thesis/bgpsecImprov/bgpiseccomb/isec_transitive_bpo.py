from typing import TYPE_CHECKING, Any, Optional

from bgpy.simulation_engine.policies.bgp import BGP
from bgpy.simulation_engine.policies.thesis.bgpsecImprov import BGPSecCryptBPO

if TYPE_CHECKING:
    from bgpy.as_graphs import AS
    from bgpy.enums import Relationships
    from bgpy.simulation_engine.announcement import Announcement as Ann
    from bgpy.simulation_framework import Scenario

from bgpy.thesis.graph_data_aggregator_time import GraphDataAggregatorTime
import time


class BPOBGPiSecCryptTransitive(BGPSecCryptBPO):
    """Represents BGPiSec Transitive attributes"""

    name = "BGP-iSec Crypt Transitive Only with BPO"

    ### i didn't really refractor this class / remove unnecessary overrides in this class, so this could probably still be improved in the future

    ###########################
    # BGPiSec Transitive Part #
    ###########################

    _get_best_ann_by_gao_rexford = BGP._get_best_ann_by_gao_rexford 
    seed_ann = BGP.seed_ann

    
    def _policy_propagate(
        self,
        neighbor: "AS",
        ann: "Ann",
        propagate_to: "Relationships",
        send_rels: set["Relationships"],
    ) -> bool:
        """Sets BGPSec fields when propagating"""

        if(self.as_.signing_key is not None):
            ### Check if already in bgpsec_as_path since else it gets added twice when seeding ann
            bgpsec_as_path = ann.bgpsec_as_path
            if(self.as_.asn not in bgpsec_as_path):
                bgpsec_as_path = (self.as_.asn, *bgpsec_as_path)

            sig_list = ann.bgpsec_signatures
            update_hash = self.create_ann_hash(ann.prefix, neighbor.asn, ann.as_path, sig_list)
            sig = (self.as_.asn, self.create_signature(update_hash)) ### creates signature over important attributes

            if(sig_list):
                sig_list = (sig, *sig_list)
            else:
               sig_list = (sig,)

        send_ann = ann.copy(
            {"bgpsec_next_asn": neighbor.asn, "bgpsec_as_path": bgpsec_as_path, "bgpsec_signatures": sig_list}
        )
        self._process_outgoing_ann(neighbor, send_ann, propagate_to, send_rels)
        return True

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
            if(asn == self.as_.asn):
                continue
            if asn not in bgpsec_signatures and isinstance(
                as_graph.as_dict[asn].policy, BPOBGPiSecCryptTransitive
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
                as_obj.policy, BPOBGPiSecCryptTransitive
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


    ####################
    #     BPO Part     #
    ####################

    def process_incoming_anns(
        self,
        *,
        from_rel: "Relationships",
        propagation_round: int,
        scenario: "Scenario",
        reset_q: bool = True,
    ) -> None:
        """
        "Process all announcements that were incoming from a specific rel"

        Here we want to include Crypgraphie only if it could be the new best path
        """
        verification_counts_this_round: list[int] = []

        # For each announcement that was incoming
        for prefix, ann_list in self.recv_q.items():
            # Get announcement currently in local rib
            current_ann: Ann | None = self.local_rib.get(prefix)
            og_ann = current_ann
            ann_ref : Optional["Ann"] = None
            announcement_list = ann_list
            self._verification_counter = 0

            # for this prefix, check every announcement received to get the best one
            while(len(announcement_list) > 0): ### while loop to check all valid anns for bgpsec validity
                for new_ann in announcement_list:
                    ## to implement grace period instead of hard cutoff to new main policy, best ann by other metrics remains if no bgpsec valid ann is found in received Anns
                    candidate = self._get_new_best_ann(current_ann, new_ann, from_rel)
                    if(candidate is not current_ann):
                        current_ann = candidate
                        ann_ref = new_ann
                       
                if og_ann == current_ann or current_ann is None:
                ### if all announcements are None / no better Announcement was found using normal metrics, then no further itteration is needed
                    break

                assert current_ann, "mypy type check"
                assert current_ann.seed_asn in (None, self.as_.asn), "Seed ASN is wrong"
                
                if(self._bgpisec_trans_verification(current_ann, from_rel)):
                    self.local_rib.add_ann(current_ann)
                    break
                else:
                    current_ann = og_ann
                announcement_list = [a for a in announcement_list if a is not ann_ref]
            ### no fallback here, since thats how its made in the original bgpisec_transitive class (via valid_ann there)
            
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


    def process_inc_ann_list(
        self,
        og_ann: Optional["Ann"],
        ann_list: list["Ann"],
        from_rel: "Relationships",
    ) -> Optional["Ann"]:
        current_ann = og_ann
        ann_ref : Optional["Ann"] = None
        
        for new_ann in ann_list:
            candidate = self._get_new_best_ann(current_ann, new_ann, from_rel)
            if(candidate is not current_ann):
                current_ann = candidate
                ann_ref = new_ann
            

        # This is a new best ann. Process it and add it to the local rib **if bgpsec valid**
        if (og_ann != current_ann):
            assert current_ann, "mypy type check"
            assert current_ann.seed_asn in (None, self.as_.asn), "Seed ASN is wrong"

            if(not self._bgpisec_trans_verification(current_ann, from_rel)):
                ann_list = [a for a in ann_list if a is not ann_ref]
                current_ann = self.process_inc_ann_list(og_ann=og_ann, ann_list=ann_list, from_rel=from_rel)
            
            return current_ann
        else: 
            return og_ann

