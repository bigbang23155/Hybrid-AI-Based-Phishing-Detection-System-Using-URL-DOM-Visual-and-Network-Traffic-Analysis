import unittest
import numpy as np
from .sensitivity import joint_bins, standardized_weights, PLAN

class SensitivityTests(unittest.TestCase):
    def test_training_cuts_only_and_ties(self):
        cuts,b=joint_bins([10,30],[2,6],[1,20,100,20],[1,4,1,3])
        self.assertEqual(cuts,[20,4]);self.assertEqual(b.tolist(),[0,3,2,2])
    def test_equal_joint_class_mass(self):
        y=[0,0,1,0,1,1];b=[0,0,0,1,1,1]
        w=standardized_weights(y,b)
        np.testing.assert_allclose(w,[.125,.125,.25,.25,.125,.125])
        self.assertAlmostEqual(w.sum(),1)
    def test_missing_common_support_and_bootstrap(self):
        self.assertIsNone(standardized_weights([0,1],[0,1]))
        w=standardized_weights([0,1,0],[0,0,1]);np.testing.assert_allclose(w,[.5,.5,0])
        self.assertIsNone(standardized_weights([0,1],[0,0],[1,0],support=[0]))
    def test_explicit_no_test_plan(self):
        self.assertEqual(PLAN['partitions'],['train','validation'])
        self.assertFalse(PLAN['new_test_evaluation']);self.assertEqual(PLAN['fits'],12)

if __name__=='__main__':unittest.main()
