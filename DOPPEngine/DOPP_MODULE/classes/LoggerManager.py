import logging
import sys
import traceback


class LoggerManager:
    """
    Class made to manage Logging
    """

    def __init__(self, logger_name, log_file_path, level) -> None:
        """
        LoggerManager constructor
        """

        self.d_logLevel = {"DEBUG": logging.DEBUG, "INFO": logging.INFO, "WARNING": logging.WARNING,
                           "ERROR": logging.ERROR, "CRITICAL": logging.CRITICAL}
        self.logLevel = self.d_logLevel.get(level, logging.INFO)
        self.logger_name = logger_name
        self.log_file_path = log_file_path
        self.warning_header = "[WARNING]"
        self.start_header = "[START]"
        self.stop_header = "[STOP]"
        self.finished_header = "[FINISHED]"
        self.success_header = "[SUCCESS]"
        self.failed_header = "[FAILED]"
        self.info_header = "[INFO]"
        self.parsing_header = "[PARSING]"
        self.my_logger = self.initialise_logging()
        self.spacer = "\n#######################################################################################\n"

    def get_logger(self):
        """
        Function that return the logger object
        :return: logger object ready to log
        :rtype: LoggerManager
        """
        return self.my_logger

    def initialise_logging(self):
        """
        Function to initialise the logger obhect
        :return:
        :rtype:
        """

        try:
            logger = logging.getLogger(self.logger_name)
            logger.setLevel(self.logLevel)

            formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')

            stdout_handler = logging.StreamHandler(sys.stderr)
            stdout_handler.setLevel(self.logLevel)
            stdout_handler.setFormatter(formatter)
            logger.addHandler(stdout_handler)

            fh = logging.FileHandler(self.log_file_path)
            fh.setLevel(self.logLevel)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            return logger
        except:
            sys.stderr.write("\nerror initializing logging function {}\n".format(traceback.format_exc()))

    def print_info_start(self, msg):
        self.my_logger.info("{} {}".format(self.start_header, msg))

    def print_info_start_sub_1(self, msg):

        self.my_logger.info("-->{} {}".format(self.start_header, msg))

    def print_info_start_sub_2(self, msg):
        self.my_logger.info("---->{} {}".format(self.start_header, msg))

    def print_info_stop(self, msg):
        self.my_logger.info("{} {}".format(self.stop_header, msg))

    def print_info_stop_sub_1(self, msg):
        self.my_logger.info("-->{} {}".format(self.stop_header, msg))

    def print_info_stop_sub_2(self, msg):
        self.my_logger.info("---->{} {}".format(self.stop_header, msg))

    def print_info_success(self, msg):
        self.my_logger.info("{} {}".format(self.success_header, msg))

    def print_info_success_sub_1(self, msg):
        self.my_logger.info("-->{} {}".format(self.success_header, msg))

    def print_info_success_sub_2(self, msg):
        self.my_logger.info("---->{} {}".format(self.success_header, msg))

    def print_info_failed(self, msg):
        self.my_logger.info("{} {}".format(self.failed_header, msg))

    def print_info_failed_sub_1(self, msg):
        self.my_logger.info("-->{} {}".format(self.failed_header, msg))

    def print_info_failed_sub_2(self, msg):
        self.my_logger.info("---->{} {}".format(self.failed_header, msg))

    def print_info_finished(self, msg):
        self.my_logger.info("{} {}".format(self.finished_header, msg))

    def print_info_finished_sub_1(self, msg):
        self.my_logger.info("-->{} {}".format(self.finished_header, msg))

    def print_info_finished_sub_2(self, msg):
        self.my_logger.info("---->{} {}".format(self.finished_header, msg))

    def print_info(self, msg):
        self.my_logger.info("{} {}".format(self.info_header, msg))

    def print_info_sub_1(self, msg):
        self.my_logger.info("-->{} {}".format(self.info_header, msg))

    def print_info_sub_2(self, msg):
        self.my_logger.info("---->{} {}".format(self.info_header, msg))

    def print_debug(self, msg):
        self.my_logger.debug("{} {}".format(self.info_header, msg))

    def print_debug_sub_1(self, msg):
        self.my_logger.debug("-->{} {}".format(self.info_header, msg))

    def print_debug_sub_2(self, msg):
        self.my_logger.debug("---->{} {}".format(self.info_header, msg))

    def print_debug_start(self, msg):
        self.my_logger.debug("{} {}".format(self.start_header, msg))

    def print_debug_start_sub_1(self, msg):
        self.my_logger.debug("-->{} {}".format(self.start_header, msg))

    def print_debug_start_sub_2(self, msg):
        self.my_logger.debug("---->{} {}".format(self.start_header, msg))

    def print_debug_stop(self, msg):
        self.my_logger.debug("{} {}".format(self.stop_header, msg))

    def print_debug_stop_sub_1(self, msg):
        self.my_logger.debug("-->{} {}".format(self.stop_header, msg))

    def print_debug_stop_sub_2(self, msg):
        self.my_logger.debug("---->{} {}".format(self.stop_header, msg))

    def print_debug_success(self, msg):
        self.my_logger.debug("{} {}".format(self.success_header, msg))

    def print_debug_success_sub1(self, msg):
        self.my_logger.debug("-->{} {}".format(self.success_header, msg))

    def print_debug_success_sub2(self, msg):
        self.my_logger.debug("---->{} {}".format(self.success_header, msg))

    def print_debug_failed(self, msg):
        self.my_logger.debug("{} {}".format(self.failed_header, msg))

    def print_debug_failed_sub_1(self, msg):
        self.my_logger.debug("-->{} {}".format(self.failed_header, msg))

    def print_debug_failed_sub_2(self, msg):
        self.my_logger.debug("---->{} {}".format(self.failed_header, msg))

    def print_debug_finished(self, msg):
        self.my_logger.debug("{} {}".format(self.finished_header, msg))

    def print_debug_finished_sub_1(self, msg):
        self.my_logger.debug("-->{} {}".format(self.finished_header, msg))

    def print_debug_finished_sub_2(self, msg):
        self.my_logger.debug("---->{} {}".format(self.finished_header, msg))

    def print_error_start(self, msg):
        self.my_logger.error("{} {}".format(self.start_header, msg))

    def print_error_start_sub_1(self, msg):
        self.my_logger.error("-->{} {}".format(self.start_header, msg))

    def print_error_start_sub_2(self, msg):
        self.my_logger.error("---->{} {}".format(self.start_header, msg))

    def print_error_stop(self, msg):
        self.my_logger.error("{} {}".format(self.stop_header, msg))

    def print_error_stop_sub_1(self, msg):
        self.my_logger.error("-->{} {}".format(self.stop_header, msg))

    def print_error_stop_sub_2(self, msg):
        self.my_logger.error("---->{} {}".format(self.stop_header, msg))

    def print_error_success(self, msg):
        self.my_logger.error("{} {}".format(self.success_header, msg))

    def print_error_success_sub_1(self, msg):
        self.my_logger.error("->{} {}".format(self.success_header, msg))

    def print_error_success_sub_2(self, msg):
        self.my_logger.error("---->{} {}".format(self.success_header, msg))

    def print_error_failed(self, msg):
        self.my_logger.error("{} {} {} {}".format(self.spacer, self.failed_header, msg, self.spacer))

    def print_error_finished(self, msg):
        self.my_logger.error("{} {}".format(self.finished_header, msg))

    def print_error_finished_sub_1(self, msg):
        self.my_logger.error("-->{} {}".format(self.finished_header, msg))

    def print_error_finished_sub_2(self, msg):
        self.my_logger.error("---->{} {}".format(self.finished_header, msg))

    def print_warning_start(self, msg):
        self.my_logger.warning("{} {}".format(self.start_header, msg))

    def print_warning_start_sub_1(self, msg):
        self.my_logger.warning("-->{} {}".format(self.start_header, msg))

    def print_warning_start_sub_2(self, msg):
        self.my_logger.warning("---->{} {}".format(self.start_header, msg))

    def print_warning_stop(self, msg):
        self.my_logger.warning("{} {}".format(self.stop_header, msg))

    def print_warning_stop_sub_1(self, msg):
        self.my_logger.warning("-->{} {}".format(self.stop_header, msg))

    def print_warning_stop_sub_2(self, msg):
        self.my_logger.warning("---->{} {}".format(self.stop_header, msg))

    def print_warning_success(self, msg):
        self.my_logger.warning("{} {}".format(self.success_header, msg))

    def print_warning_success_sub_1(self, msg):
        self.my_logger.warning("-->{} {}".format(self.success_header, msg))

    def print_warning_success_sub_2(self, msg):
        self.my_logger.warning("---->{} {}".format(self.success_header, msg))

    def print_warning_failed(self, msg):
        self.my_logger.warning("{} {}".format(self.failed_header, msg))

    def print_warning_failed_sub_1(self, msg):
        self.my_logger.warning("-->{} {}".format(self.failed_header, msg))

    def print_warning_failed_sub_2(self, msg):
        self.my_logger.warning("---->{} {}".format(self.failed_header, msg))

    def print_warning_finished(self, msg):
        self.my_logger.warning("{} {}".format(self.finished_header, msg))

    def print_warning_finished_sub_1(self, msg):
        self.my_logger.warning("-->{} {}".format(self.finished_header, msg))

    def print_warning_finished_sub_2(self, msg):
        self.my_logger.warning("---->{} {}".format(self.finished_header, msg))

