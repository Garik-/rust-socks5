# Rust SOCKS5

В общем идея просто, что-то написать на языке что бы его подучить

0 версия должна быть люто простая возможно на select


https://github.com/Garik-/mini_socks5

хотел сделать через select нормально, а тут в rust хрен его затщишь без unsafe, проще сразу юзать tokio и tokio::io::copy_bidirectional
