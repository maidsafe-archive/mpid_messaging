(function() {var implementors = {};
implementors['libc'] = ["impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.stat.html' title='libc::stat'>stat</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.stat64.html' title='libc::stat64'>stat64</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.pthread_attr_t.html' title='libc::pthread_attr_t'>pthread_attr_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.sigset_t.html' title='libc::sigset_t'>sigset_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.sigaction.html' title='libc::sigaction'>sigaction</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.stack_t.html' title='libc::stack_t'>stack_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.siginfo_t.html' title='libc::siginfo_t'>siginfo_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.glob64_t.html' title='libc::glob64_t'>glob64_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.ucred.html' title='libc::ucred'>ucred</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.statfs.html' title='libc::statfs'>statfs</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.msghdr.html' title='libc::msghdr'>msghdr</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.termios.html' title='libc::termios'>termios</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.flock.html' title='libc::flock'>flock</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.ipc_perm.html' title='libc::ipc_perm'>ipc_perm</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.shmid_ds.html' title='libc::shmid_ds'>shmid_ds</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.dirent.html' title='libc::dirent'>dirent</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.dirent64.html' title='libc::dirent64'>dirent64</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.rlimit64.html' title='libc::rlimit64'>rlimit64</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.glob_t.html' title='libc::glob_t'>glob_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.ifaddrs.html' title='libc::ifaddrs'>ifaddrs</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.pthread_mutex_t.html' title='libc::pthread_mutex_t'>pthread_mutex_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.pthread_rwlock_t.html' title='libc::pthread_rwlock_t'>pthread_rwlock_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.pthread_mutexattr_t.html' title='libc::pthread_mutexattr_t'>pthread_mutexattr_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.pthread_cond_t.html' title='libc::pthread_cond_t'>pthread_cond_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.passwd.html' title='libc::passwd'>passwd</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.statvfs.html' title='libc::statvfs'>statvfs</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.sockaddr_nl.html' title='libc::sockaddr_nl'>sockaddr_nl</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.dqblk.html' title='libc::dqblk'>dqblk</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.signalfd_siginfo.html' title='libc::signalfd_siginfo'>signalfd_siginfo</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.fsid_t.html' title='libc::fsid_t'>fsid_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.mq_attr.html' title='libc::mq_attr'>mq_attr</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.cpu_set_t.html' title='libc::cpu_set_t'>cpu_set_t</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.sockaddr.html' title='libc::sockaddr'>sockaddr</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.sockaddr_in.html' title='libc::sockaddr_in'>sockaddr_in</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.sockaddr_in6.html' title='libc::sockaddr_in6'>sockaddr_in6</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.sockaddr_un.html' title='libc::sockaddr_un'>sockaddr_un</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.sockaddr_storage.html' title='libc::sockaddr_storage'>sockaddr_storage</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.addrinfo.html' title='libc::addrinfo'>addrinfo</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.sockaddr_ll.html' title='libc::sockaddr_ll'>sockaddr_ll</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.fd_set.html' title='libc::fd_set'>fd_set</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.tm.html' title='libc::tm'>tm</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.sched_param.html' title='libc::sched_param'>sched_param</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.Dl_info.html' title='libc::Dl_info'>Dl_info</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.epoll_event.html' title='libc::epoll_event'>epoll_event</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.utsname.html' title='libc::utsname'>utsname</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.utimbuf.html' title='libc::utimbuf'>utimbuf</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.timeval.html' title='libc::timeval'>timeval</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.timespec.html' title='libc::timespec'>timespec</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.rlimit.html' title='libc::rlimit'>rlimit</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.rusage.html' title='libc::rusage'>rusage</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.in_addr.html' title='libc::in_addr'>in_addr</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.in6_addr.html' title='libc::in6_addr'>in6_addr</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.ip_mreq.html' title='libc::ip_mreq'>ip_mreq</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.ipv6_mreq.html' title='libc::ipv6_mreq'>ipv6_mreq</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.hostent.html' title='libc::hostent'>hostent</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.iovec.html' title='libc::iovec'>iovec</a>","impl <a class='trait' href='core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libc/struct.pollfd.html' title='libc::pollfd'>pollfd</a>",];implementors['log'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='log/enum.LogLevel.html' title='log::LogLevel'>LogLevel</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='log/enum.LogLevelFilter.html' title='log::LogLevelFilter'>LogLevelFilter</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='log/struct.LogLocation.html' title='log::LogLocation'>LogLocation</a>",];implementors['time'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='time/struct.Duration.html' title='time::Duration'>Duration</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='time/struct.Timespec.html' title='time::Timespec'>Timespec</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='time/struct.PreciseTime.html' title='time::PreciseTime'>PreciseTime</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='time/struct.SteadyTime.html' title='time::SteadyTime'>SteadyTime</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='time/struct.Tm.html' title='time::Tm'>Tm</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='time/enum.ParseError.html' title='time::ParseError'>ParseError</a>",];implementors['aho_corasick'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='aho_corasick/struct.Match.html' title='aho_corasick::Match'>Match</a>",];implementors['regex_syntax'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='regex_syntax/enum.Repeater.html' title='regex_syntax::Repeater'>Repeater</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='regex_syntax/struct.ClassRange.html' title='regex_syntax::ClassRange'>ClassRange</a>","impl&lt;NodeRef, Type, NodeType&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='https://doc.rust-lang.org/nightly/collections/btree/node/struct.Handle.html' title='collections::btree::node::Handle'>Handle</a>&lt;NodeRef, Type, NodeType&gt; <span class='where'>where NodeRef: <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a>, Type: <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a>, NodeType: <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a></span>","impl&lt;E&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='https://doc.rust-lang.org/nightly/collections/enum_set/struct.EnumSet.html' title='collections::enum_set::EnumSet'>EnumSet</a>&lt;E&gt;","impl&lt;T&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='https://doc.rust-lang.org/nightly/collections/linked_list/struct.Rawlink.html' title='collections::linked_list::Rawlink'>Rawlink</a>&lt;T&gt;","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='https://doc.rust-lang.org/nightly/collections/string/enum.ParseError.html' title='collections::string::ParseError'>ParseError</a>","impl&lt;T&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='https://doc.rust-lang.org/nightly/collections/enum.Bound.html' title='collections::Bound'>Bound</a>&lt;T&gt; <span class='where'>where T: <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a></span>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='https://doc.rust-lang.org/nightly/alloc/boxed/struct.ExchangeHeapSingleton.html' title='alloc::boxed::ExchangeHeapSingleton'>ExchangeHeapSingleton</a>",];implementors['libsodium_sys'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libsodium_sys/struct.crypto_auth_hmacsha256_state.html' title='libsodium_sys::crypto_auth_hmacsha256_state'>crypto_auth_hmacsha256_state</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libsodium_sys/struct.crypto_auth_hmacsha512_state.html' title='libsodium_sys::crypto_auth_hmacsha512_state'>crypto_auth_hmacsha512_state</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libsodium_sys/struct.crypto_hash_sha256_state.html' title='libsodium_sys::crypto_hash_sha256_state'>crypto_hash_sha256_state</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='libsodium_sys/struct.crypto_hash_sha512_state.html' title='libsodium_sys::crypto_hash_sha512_state'>crypto_hash_sha512_state</a>",];implementors['rand'] = ["impl&lt;X: <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a>&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/range/struct.Range.html' title='rand::distributions::range::Range'>Range</a>&lt;X&gt;","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/gamma/struct.Gamma.html' title='rand::distributions::gamma::Gamma'>Gamma</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/gamma/struct.ChiSquared.html' title='rand::distributions::gamma::ChiSquared'>ChiSquared</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/gamma/struct.FisherF.html' title='rand::distributions::gamma::FisherF'>FisherF</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/gamma/struct.StudentT.html' title='rand::distributions::gamma::StudentT'>StudentT</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/normal/struct.StandardNormal.html' title='rand::distributions::normal::StandardNormal'>StandardNormal</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/normal/struct.Normal.html' title='rand::distributions::normal::Normal'>Normal</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/normal/struct.LogNormal.html' title='rand::distributions::normal::LogNormal'>LogNormal</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/exponential/struct.Exp1.html' title='rand::distributions::exponential::Exp1'>Exp1</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/exponential/struct.Exp.html' title='rand::distributions::exponential::Exp'>Exp</a>","impl&lt;Sup&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/struct.RandSample.html' title='rand::distributions::RandSample'>RandSample</a>&lt;Sup&gt;","impl&lt;T: <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a>&gt; <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/distributions/struct.Weighted.html' title='rand::distributions::Weighted'>Weighted</a>&lt;T&gt;","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/isaac/struct.IsaacRng.html' title='rand::isaac::IsaacRng'>IsaacRng</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/isaac/struct.Isaac64Rng.html' title='rand::isaac::Isaac64Rng'>Isaac64Rng</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/chacha/struct.ChaChaRng.html' title='rand::chacha::ChaChaRng'>ChaChaRng</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/reseeding/struct.ReseedWithDefault.html' title='rand::reseeding::ReseedWithDefault'>ReseedWithDefault</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rand/struct.StdRng.html' title='rand::StdRng'>StdRng</a>",];implementors['regex'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for Char","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for InputAt","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for EmptyLook",];implementors['rustc_serialize'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='rustc_serialize/base64/enum.CharacterSet.html' title='rustc_serialize::base64::CharacterSet'>CharacterSet</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='rustc_serialize/base64/enum.Newline.html' title='rustc_serialize::base64::Newline'>Newline</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='rustc_serialize/base64/struct.Config.html' title='rustc_serialize::base64::Config'>Config</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='rustc_serialize/base64/enum.FromBase64Error.html' title='rustc_serialize::base64::FromBase64Error'>FromBase64Error</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='rustc_serialize/hex/enum.FromHexError.html' title='rustc_serialize::hex::FromHexError'>FromHexError</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='rustc_serialize/json/enum.ErrorCode.html' title='rustc_serialize::json::ErrorCode'>ErrorCode</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='rustc_serialize/json/enum.EncoderError.html' title='rustc_serialize::json::EncoderError'>EncoderError</a>",];implementors['cbor'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='cbor/enum.Type.html' title='cbor::Type'>Type</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='cbor/enum.CborUnsigned.html' title='cbor::CborUnsigned'>CborUnsigned</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='cbor/enum.CborSigned.html' title='cbor::CborSigned'>CborSigned</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='enum' href='cbor/enum.CborFloat.html' title='cbor::CborFloat'>CborFloat</a>",];implementors['sodiumoxide'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/struct.PublicKey.html' title='sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey'>PublicKey</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/struct.Nonce.html' title='sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce'>Nonce</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/sign/ed25519/struct.PublicKey.html' title='sodiumoxide::crypto::sign::ed25519::PublicKey'>PublicKey</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/sign/ed25519/struct.Signature.html' title='sodiumoxide::crypto::sign::ed25519::Signature'>Signature</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/sign/edwards25519sha512batch/struct.PublicKey.html' title='sodiumoxide::crypto::sign::edwards25519sha512batch::PublicKey'>PublicKey</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/scalarmult/curve25519/struct.GroupElement.html' title='sodiumoxide::crypto::scalarmult::curve25519::GroupElement'>GroupElement</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/auth/hmacsha512/struct.Tag.html' title='sodiumoxide::crypto::auth::hmacsha512::Tag'>Tag</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/auth/hmacsha512256/struct.Tag.html' title='sodiumoxide::crypto::auth::hmacsha512256::Tag'>Tag</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/auth/hmacsha256/struct.Tag.html' title='sodiumoxide::crypto::auth::hmacsha256::Tag'>Tag</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/hash/sha512/struct.Digest.html' title='sodiumoxide::crypto::hash::sha512::Digest'>Digest</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/hash/sha256/struct.Digest.html' title='sodiumoxide::crypto::hash::sha256::Digest'>Digest</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/secretbox/xsalsa20poly1305/struct.Nonce.html' title='sodiumoxide::crypto::secretbox::xsalsa20poly1305::Nonce'>Nonce</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/onetimeauth/poly1305/struct.Tag.html' title='sodiumoxide::crypto::onetimeauth::poly1305::Tag'>Tag</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/pwhash/scryptsalsa208sha256/struct.OpsLimit.html' title='sodiumoxide::crypto::pwhash::scryptsalsa208sha256::OpsLimit'>OpsLimit</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/pwhash/scryptsalsa208sha256/struct.MemLimit.html' title='sodiumoxide::crypto::pwhash::scryptsalsa208sha256::MemLimit'>MemLimit</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/pwhash/scryptsalsa208sha256/struct.Salt.html' title='sodiumoxide::crypto::pwhash::scryptsalsa208sha256::Salt'>Salt</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/pwhash/scryptsalsa208sha256/struct.HashedPassword.html' title='sodiumoxide::crypto::pwhash::scryptsalsa208sha256::HashedPassword'>HashedPassword</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/stream/xsalsa20/struct.Nonce.html' title='sodiumoxide::crypto::stream::xsalsa20::Nonce'>Nonce</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/stream/aes128ctr/struct.Nonce.html' title='sodiumoxide::crypto::stream::aes128ctr::Nonce'>Nonce</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/stream/salsa208/struct.Nonce.html' title='sodiumoxide::crypto::stream::salsa208::Nonce'>Nonce</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/stream/salsa2012/struct.Nonce.html' title='sodiumoxide::crypto::stream::salsa2012::Nonce'>Nonce</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/stream/salsa20/struct.Nonce.html' title='sodiumoxide::crypto::stream::salsa20::Nonce'>Nonce</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/stream/chacha20/struct.Nonce.html' title='sodiumoxide::crypto::stream::chacha20::Nonce'>Nonce</a>","impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='sodiumoxide/crypto/shorthash/siphash24/struct.Digest.html' title='sodiumoxide::crypto::shorthash::siphash24::Digest'>Digest</a>",];implementors['xor_name'] = ["impl <a class='trait' href='https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html' title='core::marker::Copy'>Copy</a> for <a class='struct' href='xor_name/struct.XorName.html' title='xor_name::XorName'>XorName</a>",];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()
