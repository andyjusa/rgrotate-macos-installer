/* Offline regression tests. Every reachable USB entry point is replaced below. */
#define libusb_bulk_transfer mock_bulk_transfer
#define libusb_get_device_list mock_get_device_list
#define libusb_get_device_descriptor mock_get_device_descriptor
#define libusb_free_device_list mock_free_device_list
#define libusb_open mock_open
#define libusb_init mock_init
#define main backend_main
#include "spd_dump.c"
#undef main
#include <assert.h>
#include <sys/wait.h>
#include <fcntl.h>

static spdio_t test_io;
static uint8_t raw[65542], enc[131086], incoming[131086], rx[1024];
static int incoming_len, incoming_pos, bulk_calls, mock_devices, mode, reads;
static uint64_t written;
static char input_path[128];
enum { MODE_NORMAL, MODE_WRITE_TIMEOUT, MODE_NACK_MIDST, MODE_HUGE_START, MODE_SHORT_READ, MODE_LOG_FLOOD, MODE_READ64 };

static void init_io(int flags) {
	memset(&test_io, 0, sizeof(test_io));
	test_io.raw_buf = raw; test_io.enc_buf = enc;
	test_io.temp_buf = raw + 4; test_io.recv_buf = rx;
	test_io.flags = flags; test_io.timeout = 50;
	test_io.endp_in = 0x81; test_io.endp_out = 1;
	incoming_len = incoming_pos = bulk_calls = reads = 0;
	mode = MODE_NORMAL; written = 0;
}

static void queue_response(int type, const void *data, size_t len) {
	uint8_t response_raw[65542];
	spdio_t response = test_io;
	response.raw_buf = response_raw; response.enc_buf = incoming;
	encode_msg(&response, type, data, len);
	incoming_len = response.enc_len; incoming_pos = 0;
}

int LIBUSB_CALL mock_bulk_transfer(libusb_device_handle *handle, unsigned char ep,
	unsigned char *data, int len, int *actual, unsigned int timeout) {
	(void)handle;
	assert(timeout > 0 && timeout <= 120000);
	bulk_calls++;
	*actual = 0;
	if (!(ep & 0x80)) {
		int type = READ16_BE(test_io.raw_buf);
		if (mode == MODE_WRITE_TIMEOUT) { *actual = len / 2; return LIBUSB_ERROR_TIMEOUT; }
		*actual = len;
		if (mode == MODE_HUGE_START) {
			assert(type == BSL_CMD_START_DATA);
			assert(READ16_BE(test_io.raw_buf + 2) == 88);
			assert(READ32_LE(test_io.raw_buf + 76) == 0x5e000000u);
			assert(READ32_LE(test_io.raw_buf + 80) == 1);
			queue_response(BSL_REP_VERIFY_ERROR, NULL, 0);
		} else if (mode == MODE_NACK_MIDST && type == BSL_CMD_MIDST_DATA) {
			queue_response(BSL_REP_VERIFY_ERROR, NULL, 0);
		} else if (mode == MODE_SHORT_READ && type == BSL_CMD_READ_MIDST) {
			uint8_t short_data[2] = { 0, 0 };
			queue_response(BSL_REP_READ_FLASH, short_data, sizeof(short_data));
		} else if (mode == MODE_READ64 && type == BSL_CMD_READ_START) {
			assert(READ16_BE(test_io.raw_buf + 2) == 88);
			assert(READ32_LE(test_io.raw_buf + 76) == 0x2000);
			assert(READ32_LE(test_io.raw_buf + 80) == 1);
			queue_response(BSL_REP_ACK, NULL, 0);
		} else if (mode == MODE_READ64 && type == BSL_CMD_READ_MIDST) {
			uint8_t bytes[4096] = { 0 };
			assert(READ16_BE(test_io.raw_buf + 2) == 12);
			assert(READ32_LE(test_io.raw_buf + 4) == 4096);
			assert(READ32_LE(test_io.raw_buf + 8) == 0x1000);
			assert(READ32_LE(test_io.raw_buf + 12) == 1);
			queue_response(BSL_REP_READ_FLASH, bytes, sizeof(bytes));
		} else {
			if (type == BSL_CMD_MIDST_DATA) written += READ16_BE(test_io.raw_buf + 2);
			queue_response(BSL_REP_ACK, NULL, 0);
		}
		return 0;
	}
	if (mode == MODE_LOG_FLOOD) {
		usleep(1000);
		queue_response(BSL_REP_LOG, NULL, 0);
	}
	if (incoming_pos == incoming_len) return LIBUSB_ERROR_TIMEOUT;
	if (len > incoming_len - incoming_pos) len = incoming_len - incoming_pos;
	memcpy(data, incoming + incoming_pos, len);
	incoming_pos += len; *actual = len; reads++;
	return 0;
}

ssize_t LIBUSB_CALL mock_get_device_list(libusb_context *ctx, libusb_device ***list) {
	static libusb_device *devices[3];
	(void)ctx; devices[0] = (libusb_device *)(uintptr_t)1;
	devices[1] = (libusb_device *)(uintptr_t)2; devices[2] = NULL;
	*list = devices; return mock_devices;
}
int LIBUSB_CALL mock_get_device_descriptor(libusb_device *dev, struct libusb_device_descriptor *desc) {
	(void)dev; memset(desc, 0, sizeof(*desc));
	desc->idVendor = 0x1782; desc->idProduct = 0x4d00; return 0;
}
void LIBUSB_CALL mock_free_device_list(libusb_device **list, int unref) { (void)list; (void)unref; }
int LIBUSB_CALL mock_open(libusb_device *dev, libusb_device_handle **handle) {
	(void)dev; (void)handle;
	assert(!"USB open must not occur during offline tests"); return LIBUSB_ERROR_OTHER;
}
int LIBUSB_CALL mock_init(libusb_context **ctx) {
	(void)ctx; assert(!"USB init must not occur during offline tests"); return LIBUSB_ERROR_OTHER;
}

static void confirm_input(void) {
	int fds[2]; assert(pipe(fds) == 0);
	assert(write(fds[1], "yes\n", 4) == 4); close(fds[1]);
	assert(dup2(fds[0], STDIN_FILENO) >= 0); close(fds[0]);
}

static void bad_name(void) { select_partition(&test_io, "012345678901234567890123456789012345", 1, 0, BSL_CMD_START_DATA); }
static void bad_size(void) { select_partition(&test_io, "super", UINT64_C(0x100000000), 0, BSL_CMD_START_DATA); }
static void bad_suffix(void) { (void)str_to_size("18446744073709551615G"); }
static void bad_decimal(void) { (void)str_to_size("18446744073709551616"); }
static void bad_wait(void) { (void)bounded_decimal("31", 0, 30); }
static void duplicate_devices(void) { mock_devices = 2; (void)open_unique_device(); }
static void forbidden_command(void) {
	char *args[] = { "spd_dump", "read_part", "boot_a", "0", "4096", "/tmp/read", "erase_part", "userdata" };
	validate_readonly_commands(8, args);
}
static void too_many_loaders(void) {
	char *args[] = { "spd_dump", "fdl", "one", "1", "fdl", "two", "2", "fdl", "three", "3" };
	validate_readonly_commands(10, args);
}
static void missing_delimiter(void) {
	queue_response(BSL_REP_ACK, NULL, 0); incoming_len--;
	(void)recv_msg(&test_io);
}
static void checksum_error(void) {
	queue_response(BSL_REP_ACK, NULL, 0); incoming[2] ^= 1;
	(void)recv_msg(&test_io);
}
static void timeout_write(void) {
	mode = MODE_WRITE_TIMEOUT; encode_msg(&test_io, BSL_CMD_END_DATA, NULL, 0);
	(void)send_msg(&test_io);
}
static void nack_write(void) {
	confirm_input(); mode = MODE_NACK_MIDST;
	load_partition(&test_io, "test", input_path, 32768);
}
static void huge_write_header(void) {
	confirm_input(); mode = MODE_HUGE_START;
	load_partition(&test_io, "super", input_path, 32768);
}
static void short_read(void) {
	mode = MODE_SHORT_READ;
	(void)dump_partition(&test_io, "boot_a", 0, 4096, "/dev/null", 4096);
}
static void successful_write(void) {
	confirm_input();
	load_partition(&test_io, "test", input_path, 32768);
	assert(written == 70000);
}
static void expect_failure(void (*test)(void), const char *name) {
	pid_t child; int status;
	fflush(NULL); child = fork(); assert(child >= 0);
	if (!child) { init_io(FLAGS_CRC16 | FLAGS_TRANSCODE); test(); exit(0); }
	assert(waitpid(child, &status, 0) == child);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 1) {
		fprintf(stderr, "expected fail-closed exit for %s, got %d\n", name, status); abort();
	}
}

int main(void) {
	int fd, flags; unsigned i;
	uint8_t payload[] = { 0x7e, 0x7d, 0, 0xff };
	char *valid[] = { "spd_dump", "--read-only", "--check-commands", "--wait", "0",
		"fdl", "official1", "0x5500", "fdl", "official2", "0x9efffe00",
		"partition_list", "/tmp/list", "read_part", "boot_a", "0", "4096", "/tmp/read" };
	assert(backend_main((int)(sizeof(valid)/sizeof(valid[0])), valid) == 0);
	assert(spd_crc16(0, "123456789", 9) == 0x31c3);
	init_io(FLAGS_CRC16 | FLAGS_TRANSCODE);
	select_partition(&test_io, "super", UINT64_C(5872025600), 1, BSL_CMD_START_DATA);
	assert(test_io.raw_len == 94 && READ16_BE(raw + 2) == 88);
	assert(READ32_LE(raw + 76) == 0x5e000000u && READ32_LE(raw + 80) == 1);
	for (i = 84; i < 92; i++) assert(raw[i] == 0);
	select_partition(&test_io, "userdata", 0, 0, BSL_CMD_ERASE_FLASH);
	assert(READ16_BE(raw) == 0x0a && READ16_BE(raw + 2) == 76 && READ32_LE(raw + 76) == 0);
	for (flags = 0; flags <= FLAGS_TRANSCODE; flags += FLAGS_TRANSCODE) {
		init_io(FLAGS_CRC16 | flags);
		queue_response(BSL_REP_READ_FLASH, payload, sizeof(payload));
		assert(recv_msg(&test_io) == 10 && !memcmp(raw + 4, payload, sizeof(payload)));
	}
	expect_failure(bad_name, "unterminated name");
	expect_failure(bad_size, "32-bit truncation");
	expect_failure(bad_suffix, "suffix overflow");
	expect_failure(bad_decimal, "decimal overflow");
	expect_failure(bad_wait, "unbounded wait");
	expect_failure(duplicate_devices, "multiple USB devices");
	expect_failure(forbidden_command, "write after read");
	expect_failure(too_many_loaders, "third loader");
	expect_failure(missing_delimiter, "missing final delimiter");
	expect_failure(checksum_error, "checksum error");
	expect_failure(timeout_write, "partial USB write timeout");
	expect_failure(short_read, "short partition read");
	snprintf(input_path, sizeof(input_path), "/tmp/rgrotate-protocol-XXXXXX");
	fd = mkstemp(input_path); assert(fd >= 0);
	assert(ftruncate(fd, 70000) == 0);
	{
		pid_t child; int status;
		fflush(NULL); child = fork(); assert(child >= 0);
		if (!child) { init_io(FLAGS_CRC16 | FLAGS_TRANSCODE); successful_write(); exit(0); }
		assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	expect_failure(nack_write, "MIDST NACK");
	assert(ftruncate(fd, (off_t)5872025600LL) == 0);
	expect_failure(huge_write_header, "5.8 GB streamed file header");
	close(fd); unlink(input_path);
	init_io(FLAGS_CRC16 | FLAGS_TRANSCODE); mode = MODE_READ64;
	assert(dump_partition(&test_io, "super", UINT64_C(0x100001000), 4096, "/dev/null", 4096) == UINT64_C(0x100002000));
	init_io(FLAGS_CRC16 | FLAGS_TRANSCODE); test_io.timeout = 10; mode = MODE_LOG_FLOOD;
	assert(recv_msg(&test_io) == 0 && reads < 100);
	puts("Offline protocol regression tests passed; no USB device was opened.");
	return 0;
}
