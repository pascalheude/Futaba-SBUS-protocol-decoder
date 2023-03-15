# Futaba SBUS High Level Analyzer (SBUS-HLA)
# Copyright 2023, Pascal HEUDE
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

import enum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    #my_string_setting = StringSetting()
    #my_number_setting = NumberSetting(min_value=0, max_value=100)
    #my_choices_setting = ChoicesSetting(choices=('A', 'B'))

    result_types = {
        'sbus_start_sync_byte': {
            'format': 'Start sync byte'
        },
        'sbus_payload': {
            'format': 'PAYLOAD: {{data.payload}}'
        },
        'sbus_end_sync_byte': {
            'format': 'End sync byte'
        }
    }

    # Decoder FSM
    class dec_fsm_e(enum.Enum):
        idle = 1
        #start_sync_byte = 2  # No being used - If sync byte is detected the state changes from idle -> payload
        payload = 3
        stop_sync_byte = 4

    # Protocol defines
    SBUS_START_SYNC_BYTE = b'\x0f'  # 0x0F
    SBUS_STOP_SYNC_BYTE = b'\x00'  # 0x00

    def __init__(self):

        # Initialize HLA.
        self.sbus_frame_start = None  # Timestamp: Start of frame
        self.sbus_frame_end = None  # Timestamp: End of frame
        self.dec_fsm = self.dec_fsm_e.idle  # Current state of protocol decoder FSM
        self.sbus_frame_current_index = 0  # Index to determine end of payload
        self.sbus_payload = []  # Stores the payload for decoding after last byte ist rx'd.
        self.sbus_payload_start = None  # Timestamp: Start of payload (w/o frame type)
        self.sbus_payload_end = None  # Timestamp: End of payload
        print("Initialized SBUS HLA.")

        # Settings can be accessed using the same name used above.

        #print("Settings:", self.my_string_setting,
        #      self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        # New frame
        if self.sbus_frame_start == None and frame.data['data'] == self.SBUS_START_SYNC_BYTE and self.dec_fsm == self.dec_fsm_e.idle:
            print('Start sync byte detected.')
            self.sbus_frame_start = frame.start_time
            self.dec_fsm = self.dec_fsm_e.payload
            self.sbus_frame_current_index += 1
            return AnalyzerFrame('START', frame.start_time, frame.end_time, {})

        # Payload
        if self.dec_fsm == self.dec_fsm_e.payload:
            payload = int.from_bytes(frame.data['data'], byteorder='big')
            if self.sbus_frame_current_index == 1:  # First payload byte
                self.sbus_payload_start = frame.start_time
                self.sbus_payload.append(payload)
                self.sbus_frame_current_index += 1
                #print('Payload start ({}): {:2x}'.format(self.sbus_frame_current_index, payload))
            elif self.sbus_frame_current_index < 23:  # ... still collecting payload bytes ...
                self.sbus_payload.append(payload)
                self.sbus_frame_current_index += 1
                #print('Adding payload ({}): {:2x}'.format(self.sbus_frame_current_index, payload))
            elif self.sbus_frame_current_index == 23:  # Last payload byte received
                analyzerframe = None
                self.dec_fsm = self.dec_fsm_e.stop_sync_byte
                self.sbus_payload_end = frame.end_time
                self.sbus_payload.append(payload)
                #print('Payload complete ({}): {:2x}'.format(self.sbus_frame_current_index, payload))
                #print(self.sbus_payload)
                # RC channels packed
                # 11 bits per channel, 16 channels, 176 bits (22 bytes) total
                bin_str = ''
                channels = []
                for i in self.sbus_payload:
                    bin_str += format(i, '08b')[::-1]  # Format as bits and reverse order
                print(bin_str)
                for i in range(16):
                    value = int(bin_str[0 + 11 * i : 11 + 11 * i][::-1], 2)  # 'RC' value
                    value_ms = int((value * 1024 / 1639) + 881)  # Converted to milliseconds
                    channels.append(value)
                    channels.append(value_ms)
                print(channels)
                payload_str = ('Ch1: {} ({} ms), Ch2: {} ({} ms), Ch3: {} ({} ms), Ch4: {} ({} ms), ' + \
                               'Ch5: {} ({} ms), Ch6: {} ({} ms), Ch7: {} ({} ms), Ch8: {} ({} ms), ' + \
                               'Ch9: {} ({} ms), Ch10: {} ({} ms), Ch11: {} ({} ms), Ch12: {} ({} ms), ' + \
                               'Ch13: {} ({} ms), Ch14: {} ({} ms), Ch15: {} ({} ms), Ch16: {} ({} ms)').format(*channels)
                print(payload_str)
                analyzerframe = AnalyzerFrame('sbus_payload', self.sbus_payload_start, frame.end_time, {
                        'payload': payload_str})
                return analyzerframe

        # Stop sync byte
        if self.dec_fsm == self.dec_fsm_e.stop_sync_byte and frame.data['data'] == self.SBUS_STOP_SYNC_BYTE:
            print('Stop sync byte detected.')
            # And initialize again for next frame
            self.sbus_frame_start = None
            self.sbus_frame_end = None
            self.dec_fsm = self.dec_fsm_e.idle
            self.sbus_frame_current_index = 0
            self.sbus_payload = []
            self.sbus_payload_start = None
            self.sbus_payload_end = None
            return AnalyzerFrame('STOP', frame.start_time, frame.end_time, {})
