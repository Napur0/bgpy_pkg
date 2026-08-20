from typing import TYPE_CHECKING, Any, Optional

from bgpy.shared.exceptions import GaoRexfordError
from bgpy.simulation_engine.policies.bgpsec import BGPSec

if TYPE_CHECKING:
    from bgpy.as_graphs import AS
    from bgpy.shared.enums import Relationships
    from bgpy.simulation_engine.announcement import Announcement as Ann
    from bgpy.simulation_framework import Scenario


from bgpy.simulation_engine.policies.bgp import BGP




class BGPSecBPO(BGPSec):
    """
    Represents BGPSec with Cryptografic functions and processing using Best Path Only for verification instead of security third
    """

    name = "BGPSecCryptBPO"

    _get_best_ann_by_gao_rexford = BGP._get_best_ann_by_gao_rexford 
    seed_ann = BGP.seed_ann
    ### since here all validation / verification and signing will be done at the end, bgpsec_as_path will be set together with the rest at the propagation phase


    @staticmethod
    def bgpsec_valid(ann: "Ann", asn: int) -> bool: ##
        """Returns whether or not an announcement is valid by BGPSec"""
        if(asn in ann.as_path):
            as_path = ann.as_path[1:]
        else:
            as_path = ann.as_path
        bgpsec_valid = (ann.bgpsec_next_asn == asn and ann.bgpsec_as_path == as_path)
        return bgpsec_valid

    def _valid_by_bgpsec(
        self, ann: "Ann"
    ) -> bool:
        if self.bgpsec_valid(ann, self.as_.asn) :
            return True
        return False

        
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
        
        # For each prefix, get all anns recieved

        for prefix, ann_list in self.recv_q.items():
            # Get announcement currently in local rib
            current_ann: Ann | None = self.local_rib.get(prefix)
            og_ann = current_ann
            ann_ref : Optional["Ann"] = None
            announcement_list = ann_list
            first_best_fallback : Optional["Ann"] = None

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

                if(len(announcement_list) == len(ann_list)):
                    first_best_fallback = current_ann

                ### go into recursion if best ann is not valid to check if any valid ann is found in this instead
                if(self._valid_by_bgpsec(current_ann)):
                    self.local_rib.add_ann(current_ann)
                    break
                else:
                    current_ann = og_ann
                announcement_list = [a for a in announcement_list if a is not ann_ref]
            if(og_ann is None and current_ann is None): ### keeping fallback even if not bgpsec valid if no other known way to keep connection with low adoption rates
                if first_best_fallback is not None:
                    self.local_rib.add_ann(first_best_fallback)
        self._reset_q(reset_q)


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
            
            
            if(not self._valid_by_bgpsec(current_ann)):
                ann_list = [a for a in ann_list if a is not ann_ref]
                current_ann = self.process_inc_ann_list(og_ann=og_ann, ann_list=ann_list, from_rel=from_rel)

            return current_ann
        else: 
            return og_ann


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

        if isinstance(neighbor.policy, BGPSecBPO):
            next_asn = neighbor.asn
            path = (self.as_.asn, *ann.bgpsec_as_path)

        else:
            next_asn = None
            path = ()
        
        send_ann = ann.copy({"bgpsec_next_asn": next_asn, "bgpsec_as_path": path})
        self._process_outgoing_ann(neighbor, send_ann, propagate_to, send_rels)
        return True

    def _copy_and_process(
        self,
        ann: "Ann",
        recv_relationship: "Relationships",
        overwrite_default_kwargs: dict[Any, Any] | None = None,
    ) -> "Ann":
        """Sets the bgpsec_as_path.

        prepends ASN if valid, otherwise clears
        """
        bgpsec_as_path = ann.bgpsec_as_path
        bgpsec_next_as = ann.bgpsec_next_asn
        
        if overwrite_default_kwargs is None:
            overwrite_default_kwargs = {}

        overwrite_default_kwargs["bgpsec_as_path"] = overwrite_default_kwargs.get(
            "bgpsec_as_path", bgpsec_as_path
        )
        overwrite_default_kwargs["bgpsec_next_asn"] = overwrite_default_kwargs.get(
            "bgpsec_next_asn", bgpsec_next_as
        )

        return BGP._copy_and_process(
            self, ann, recv_relationship, overwrite_default_kwargs
        )