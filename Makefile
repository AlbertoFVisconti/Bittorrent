COVERAGE_LDFLAGS :=
COVERAGE_CFLAGS :=

ifeq ($(WITH_COVERAGE), 1)
COVERAGE_LDFLAGS = -lgcov --coverage
COVERAGE_CFLAGS = -fprofile-arcs -ftest-coverage
endif

COMPILE := $(CC) -c
LINK := $(CC)
SRC_DIR := src/
TEST_DIR := test/
BUILD_DIR := build/
OBJS_DIR := $(BUILD_DIR)objs/
CFLAGS := -I$(SRC_DIR)include/ -Wall -Werror -g
LDFLAGS := -lcrypto  -lcurl -lpthread $(COVERAGE_LDFLAGS)

SRCS := $(wildcard $(SRC_DIR)*.c)
OBJS := $(SRCS:$(SRC_DIR)%.c=$(OBJS_DIR)%.o)
DEPENDS := $(OBJS:%.o=%.d)


TEST_BUILD_DIR := $(BUILD_DIR)tests/
TEST_OBJS_DIR := $(TEST_BUILD_DIR)objs/

TESTS := $(wildcard $(TEST_DIR)*.c)
TEST_OBJS := $(TESTS:$(TEST_DIR)%.c=$(TEST_OBJS_DIR)%.o)
TEST_DEPENDS := $(TEST_OBJS:%.o=%.d)

UNITY_TESTS := $(wildcard $(TEST_DIR)*.c)
UNITY_TESTS_OBJS := $(UNITY_TESTS:$(TEST_DIR)%.c=$(TEST_OBJS_DIR)%.o)
UNITY_DIR := unity/src/
UNITY_FIXTURE_DIR := unity/extras/fixture/src/
UNITY_MEMORY_DIR := unity/extras/memory/src/

UNITY_OBJS := $(TEST_OBJS_DIR)unity.o \
  $(TEST_OBJS_DIR)unity_fixture.o \
  $(TEST_OBJS_DIR)unity_memory.o

CFLAGS_TESTS := -I$(UNITY_DIR) -I$(UNITY_FIXTURE_DIR) -I$(UNITY_MEMORY_DIR)


.PHONY: all
all: $(BUILD_DIR)bittorrent $(TEST_BUILD_DIR)run_tests

$(BUILD_DIR)bittorrent: $(OBJS) | build_dir
	$(LINK) -o $@ $^ $(LDFLAGS)

$(OBJS_DIR)%.o: $(SRC_DIR)%.c | build_dir
	$(CC) $(CFLAGS) -MM -MP -MT '$@' -o $(patsubst %.o,%.d,$@) $<
	$(COMPILE) $(CFLAGS) -c $(COVERAGE_CFLAGS) -o $@ $<

.PHONY: check
check: $(TEST_BUILD_DIR)run_tests
	@./$<

.PHONY: check-valgrind
check-valgrind: $(TEST_BUILD_DIR)run_tests
	@valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -s ./$<


$(TEST_BUILD_DIR)run_tests: $(UNITY_OBJS) \
  $(UNITY_TESTS_OBJS) \
  $(OBJS_DIR)bencode.o \
  $(OBJS_DIR)metainfo.o \
  $(OBJS_DIR)client.o \
  $(OBJS_DIR)peer_listener.o \
  $(OBJS_DIR)peer.o \
  $(OBJS_DIR)tracker_connection.o \
  $(TEST_OBJS_DIR)run_tests.o | build_dir
	$(LINK) -o $@ $^ $(LDFLAGS)


$(TEST_OBJS_DIR)%.o: $(TEST_DIR)%.c | build_dir
	$(CC) $(CFLAGS) $(CFLAGS_TESTS) -MM -MP -MT '$@' -o $(patsubst %.o,%.d,$@) $<
	$(COMPILE) $(CFLAGS) $(CFLAGS_TESTS) -o $@ $<

$(TEST_OBJS_DIR)%.o: $(UNITY_DIR)%.c | build_dir
	$(COMPILE) $(CFLAGS) $(CFLAGS_TESTS) -o $@ $<

$(TEST_OBJS_DIR)%.o: $(UNITY_FIXTURE_DIR)%.c | build_dir
	$(COMPILE) $(CFLAGS) $(CFLAGS_TESTS) -o $@ $<

$(TEST_OBJS_DIR)%.o: $(UNITY_MEMORY_DIR)%.c | build_dir
	$(COMPILE) $(CFLAGS) $(CFLAGS_TESTS) -o $@ $<


.PHONY: build_dir
build_dir: $(BUILD_DIR) $(OBJS_DIR) $(TEST_DIR) $(TEST_OBJS_DIR)

$(BUILD_DIR):
	mkdir -p $@

$(OBJS_DIR):
	mkdir -p $@

$(TEST_BUILD_DIR):
	mkdir -p $@

$(TEST_OBJS_DIR):
	mkdir -p $@


-include $(DEPENDS)
-include $(TEST_DEPENDS)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: format
format:
	indent -kr $(SRC_DIR)*.c $(SRC_DIR)*.h $(TEST_DIR)*.c $(TEST_DIR)*.h
	rm -rf $(SRC_DIR)*~ $(TEST_DIR)*~

.PHONY: coverage
coverage:
	lcov -d $(BUILD_DIR) --zerocounters
	$(MAKE) check
	lcov -d $(BUILD_DIR) --capture -o $(BUILD_DIR)coverage.info
	genhtml -o $(BUILD_DIR)coverage $(BUILD_DIR)coverage.info --legend

.PRECIOUS: %.o
.PRECIOUS: %.d
