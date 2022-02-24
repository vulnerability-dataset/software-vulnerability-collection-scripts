"""
Contains all the available static configurations
"""
import os
import sys
import multiprocessing
import json

import propheticus.configs

class Config(
    propheticus.configs.Classification,
    propheticus.configs.Clustering,
    propheticus.configs.Sampling,
    propheticus.configs.DimensionalityReduction,
    propheticus.configs.Preprocessing
):
    """
    Contains all the available static configurations

    ...

    Attributes
    ----------
    log_times : bool
        Used to control whether or not to log (show messages) regarding the execution times
    log_status : bool
        Used to control whether or not to log (show messages) regarding the status messages (non-error)
    max_alert_target_correlation : float
        Used to control whether or not to log (show messages) regarding the execution times
    max_alert_dt_feature_importance : float
        Threshold (max) to control whether or not a alert log message is displayed concerning a feature importance in DT algorithms
    use_transparency : bool
        Controls if generated images have transparent background
    publication_format : bool
        Controls if generated images contain detailed information (numbers instead of %, descriptions, ...)
    hash_config_basename : bool
        Controls if generated files' names are hashed or not
    OS_PATH : str
        Current absolute path
    framework_instance : str
        Allows controlling which source folder to use for different data; this can eventually become configurable
    framework_instance_data_path : str
        Defines the path to the datasets; controls whether it is live or not
    framework_instance_generated_path : str
        Controls which folder to use to fetch experiments results to be used for comparison
    max_thread_count : int
        Defines the max number of threads to be used
    validate_uuid : bool
        Controls where or not the user UUID is validated against the options defined in the Config.ValidUUID list
    """
    log_times = True
    """used to control whether or not to log (show messages) regarding the execution times"""

    log_status = True
    """used to control whether or not to log (show messages) regarding the status messages (non-error)"""

    max_alert_target_correlation = 0.35
    """used to control whether or not to log (show messages) regarding the execution times"""

    max_alert_dt_feature_importance = 0.35
    """threshold (max) to control whether or not a alert log message is displayed concerning a feature importance in DT algorithms"""

    use_transparency = False
    """controls if generated images have transparent background"""

    publication_format = True
    """controls if generated images contain detailed information (numbers instead of %, descriptions, ...)"""

    demonstration_mode = False

    force_configurations_log = True

    classification_conf_matrix_show_sample_count = True

    classification_save_predictions_probabilities = True
    classification_save_predictions_labels = True

    hash_config_basename = True
    """controls if generated files' names are hashed or not"""

    # framework_instance = 'failure_prediction'
    # # framework_instance = 'vulnerability_prediction'
    # """this variable allows defines the instance that will be used for configuring the framework instantiation; this can eventually become configurable"""

    thread_level = 'batch'  # NOTE: can be cv, run, batch, algorithm, best
    """defines the the level where threading is to be made"""

    # Changed by josep, and later joaoh.
    # max_thread_count = multiprocessing.cpu_count() - 1
    #max_thread_count = int(multiprocessing.cpu_count() / 2) - 1
    #max_thread_count = 5 #1
    # @Hack: This is a hacky way to include our own modules, but it works for now.
    sys.path.insert(0, os.path.normpath(os.path.join(os.path.abspath(__file__), '..', '..', '..')))
    from modules.common import GLOBAL_CONFIG
    max_thread_count = GLOBAL_CONFIG['propheticus']['max_thread_count']

    if max_thread_count > multiprocessing.cpu_count():
        exit('The number of chosen threads is higher than the number of CPUs. Redefining to MAX_CPU - 1')

    """defines the max number of threads to be used"""

    validate_uuid = False
    """controls where or not the user UUID is validated against the options defined in the Config.ValidUUID list"""

    pool_maxtasksperchild = 5

    MetricsByScenarios = {
        'Business-critical': ['f2-score', 'recall'],  # norminfrecall
        'Heightened-critical': ['informedness', 'recall'],
        'Best effort': ['f1-score', 'precision'],
        'Minimum effort': ['markedness', 'precision']
    }
    ComparisonScenarios = list(MetricsByScenarios.keys())

    ClassesMapping = {
        'Binary_Base': 0,
        'Binary_Error': 9999,

        'RemoveInvalidDeltaTL': 8,  # NOTE: used to samples which do not have enough lead time between injection and failure
        'RemoveDeltaTL': 9,  # NOTE: used to samples which are already after the lead time separation
        'RemoveAfterFailure': 10,  # NOTE: used to samples which are already after the first failure timestamp

        'Baseline': 0,
        'Event': 1
    }

    ClassesDescription = {
        ClassesMapping['Binary_Error']: 'General Error',
        ClassesMapping['RemoveInvalidDeltaTL']: 'Invalid DeltaTL',
        ClassesMapping['RemoveDeltaTL']: 'Remove DeltaTL',
        ClassesMapping['RemoveAfterFailure']: 'Remove After Failure',
    }

    InitialConfigurations = {
        'config_seed_count': 30,
        'config_grid_search': False
    }

    ValidUUID = []

    # OS_PATH = os.path.dirname(os.path.abspath(__file__)) + "/"
    OS_PATH = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd()
    """current absolute path"""

    @staticmethod
    def defineBasePaths():
        # High-level paths
        Config.framework_instances_path = os.path.join(Config.OS_PATH, 'instances')
        """this variable defines the framework instances dir"""

        Config.framework_configs_path = os.path.join(Config.OS_PATH, 'propheticus', 'configs')
        Config.framework_demo_path = os.path.join(Config.framework_configs_path, 'demo')
        Config.framework_demo_file_path = os.path.join(Config.framework_demo_path, 'complete_demonstration.xlsx')
        Config.framework_temp_persistent_path = os.path.join(Config.OS_PATH, '.temp_persisted')
        Config.framework_temp_path = os.path.join(Config.OS_PATH, '.temp')
        Config.framework_temp_thread_config_file_path = os.path.join(Config.framework_temp_path, '.thread_conf.txt')

    @staticmethod
    def defineDependentPaths(framework_instance):
        Config.framework_instance = framework_instance
        Config.framework_instance_label = framework_instance.replace('_', ' ').title()
        Config.framework_selected_instance_path = os.path.join(Config.framework_instances_path, framework_instance)
        """this variable defines the framework instance dir"""

        Config.framework_instance_artifacts_path = os.path.join(Config.OS_PATH, 'instances_artifacts', framework_instance)
        """this variable defines the framework instance dir"""

        Config.framework_instance_data_path = os.path.join(Config.framework_instance_artifacts_path, 'data')
        """defines the path to the datasets; controls whether it is live or not"""

        Config.framework_instance_generated_path = os.path.join(Config.framework_instance_artifacts_path, 'generated')  # 'temp-ensembles/generated-soft'
        """controls which folder to use to fetch experiments results to be used for comparison"""

        # Low-level paths
        Config.framework_instance_generated_analysis_path = os.path.join(Config.framework_instance_generated_path, '0-analysis')
        Config.framework_instance_generated_classification_path = os.path.join(Config.framework_instance_generated_path, '1-classification')
        Config.framework_instance_generated_clustering_path = os.path.join(Config.framework_instance_generated_path, '2-clustering')
        Config.framework_instance_generated_logs_path = os.path.join(Config.framework_instance_generated_path, '7-log')
        Config.framework_instance_generated_comparisons_path = os.path.join(Config.framework_instance_generated_path, '8-comparison')
        Config.framework_instance_generated_archive_path = os.path.join(Config.framework_instance_generated_path, '9-archive')
        Config.framework_instance_generated_persistent_path = os.path.join(Config.framework_instance_generated_path, '10-persistent')

Config.defineBasePaths()

# NOTE: THIS IS EXECUTED UPON IMPORT
if os.path.isfile(Config.framework_temp_thread_config_file_path):
    with open(Config.framework_temp_thread_config_file_path, encoding='utf-8') as f:
        ThreadConfigs = json.load(f)
        Config.defineDependentPaths(ThreadConfigs['framework_instance'])
        if ThreadConfigs['thread_level_'] is not None:
            Config.thread_level_ = ThreadConfigs['thread_level_']

