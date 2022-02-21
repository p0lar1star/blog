# Rust学习笔记

Rust入门时的杂记

## 1.Cargo.toml和Cargo.lock

你首次构建一个项目的时候，Cargo会输出一个Cargo.lock文件，里面记录了每个库使用的精确的版本。之后构建的时候会直接读取该文件并使用里面的版本。

Cargo只有在你希望它更新的时候才会更新新版本，手动修改Cargo.toml里的版本成新的版本号或者运行cargo update。

cargo update命令仅仅更新最新的兼容版本，如果你想跨不兼容的版本更新，需要手动修改Cargo.toml，下次构建的时候，Cargo会更新版本和Cargo.lock文件。

指定的版本为git仓库的场景，cargo build命令在有Cargo.lock文件的时候不会再拉仓库的最新代码，它会用Cargo.lock里面记录的版本，但是cargo update会拉最新的代码。

Cargo.lock文件是自动生成的，你不应该手动修改它。假如你的项目是一个可执行文件，你应该把Cargo.lock文件提交到代码库，这样，其他人下载构建的时候会使用相同的版本，确保构建后的二进制相同。Cargo.lock文件的修改历史记录了依赖的更新。

假如你的工程是一个普通的库，你不应该把Cargo.lock提交到代码库。你的库的使用者有自己的Cargo.lock文件，它们会忽略你库里的Cargo.lock文件。

假如你的工程是个动态库工程，不会有使用者用到你的源代码，这时也应该提交Cargo.lock文件到代码库。

## 2.