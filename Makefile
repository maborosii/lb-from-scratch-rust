# Makefile

# 设置默认目标
.PHONY: all
all: build-ebpf build-app

# 使用 cargo xtask 执行 build-ebpf 任务
.PHONY: build-ebpf
build-ebpf:
	cargo xtask build-ebpf --release

# 编译 Rust 项目，排除 ebpf 包，并针对 x86_64-unknown-linux-musl 目标进行静态链接
.PHONY: build-app
build-app:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --workspace --exclude ebpf --release --target=x86_64-unknown-linux-musl

# 清理构建生成的文件
.PHONY: clean
clean:
	cargo clean
