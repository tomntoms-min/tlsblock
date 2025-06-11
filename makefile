# 사용할 C++ 컴파일러를 g++로 지정합니다.
CXX = g++

# 컴파일 시 적용할 옵션입니다.
# -std=c++11: C++11 표준을 사용합니다.
# -Wall: 가능한 모든 컴파일 경고를 출력하여 잠재적인 문제를 미리 파악합니다.
CXXFLAGS = -std=c++11 -Wall

# 링크 시 사용할 옵션입니다.
# -lpcap: pcap 라이브러리를 링크하여 패킷 캡처 기능을 사용합니다.
LDFLAGS = -lpcap

# 최종적으로 생성될 실행 파일의 이름을 tls-block으로 지정합니다.
TARGET = tls-block

# 컴파일할 소스 코드 파일의 목록입니다. (지금은 하나입니다)
SRCS = main.cpp

# SRCS 목록의 .cpp 확장자를 .o (오브젝트 파일)로 바꾼 목록을 생성합니다.
OBJS = $(SRCS:.cpp=.o)

# 'make' 명령을 입력했을 때 기본적으로 실행될 규칙입니다.
# 최종 목표인 $(TARGET) 파일을 생성합니다.
all: $(TARGET)

# 링크 규칙입니다.
# 오브젝트 파일($(OBJS))들을 링크하여 최종 실행 파일($(TARGET))을 생성합니다.
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# 컴파일 규칙입니다.
# %.cpp 파일을 %.o 파일로 컴파일하는 방법을 정의합니다.
# -c: 링크는 하지 않고 컴파일만 진행하여 오브젝트 파일을 생성합니다.
# $@: 규칙의 목표 파일 이름 (예: tls-block.o)
# $<: 규칙의 첫 번째 의존 파일 이름 (예: tls-block.cpp)
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# 'make clean' 명령을 위한 규칙입니다.
# 컴파일 과정에서 생성된 모든 파일들을 삭제하여 프로젝트를 깨끗한 상태로 만듭니다.
clean:
	rm -f $(OBJS) $(TARGET)
