//! Teste ponta a ponta contra um servidor RFB falso em TCP local.

use super::*;
use openvnc_core::PixelFormat;
use tokio::net::TcpListener;

async fn fake_server(listener: TcpListener, drop_after_first: bool) {
    loop {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"RFB 003.008\n").await.unwrap();
        let mut v = [0u8; 12];
        s.read_exact(&mut v).await.unwrap();
        assert_eq!(&v, b"RFB 003.008\n");
        s.write_all(&[1, 1]).await.unwrap();
        let mut t = [0u8; 1];
        s.read_exact(&mut t).await.unwrap();
        assert_eq!(t[0], 1);
        s.write_all(&0u32.to_be_bytes()).await.unwrap();
        s.read_exact(&mut t).await.unwrap(); // ClientInit
        let mut init = vec![0, 2, 0, 2];
        init.extend_from_slice(&PixelFormat::RGBX8888.to_bytes());
        init.extend_from_slice(&1u32.to_be_bytes());
        init.push(b'x');
        s.write_all(&init).await.unwrap();
        // SetPixelFormat(20) + SetEncodings(4+32) + FBUpdateRequest(10)
        let mut m = [0u8; 66];
        s.read_exact(&mut m).await.unwrap();
        assert_eq!(m[0], 0);
        assert_eq!(m[20], 2);
        assert_eq!(m[56], 3);
        let mut upd = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1];
        upd.extend_from_slice(&0i32.to_be_bytes());
        upd.extend_from_slice(&[200, 100, 50, 0]);
        s.write_all(&upd).await.unwrap();
        // pedido incremental apos o update
        let mut r = [0u8; 10];
        s.read_exact(&mut r).await.unwrap();
        assert_eq!(&r[..2], &[3, 1]);
        // tecla da UI
        let mut k = [0u8; 8];
        s.read_exact(&mut k).await.unwrap();
        assert_eq!(k[0], 4);
        if drop_after_first {
            drop(s);
            continue;
        }
        let mut rest = Vec::new();
        let _ = s.read_to_end(&mut rest).await;
        return;
    }
}

fn wait_for(sess: &Session, pred: impl Fn(&SessionEvent) -> bool) -> SessionEvent {
    loop {
        let e = sess
            .wait_event(Duration::from_secs(10))
            .expect("timeout esperando evento");
        if pred(&e) {
            return e;
        }
    }
}

#[test]
fn end_to_end_update_input_and_reconnect() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    rt.spawn(fake_server(listener, true));
    let mut opts = ConnectOptions::new(addr);
    opts.backoff = Backoff::new(Duration::from_millis(10), Duration::from_millis(50), 3);
    let sess = Session::spawn(rt.handle(), opts, Arc::new(|| {}));

    for round in 0..2 {
        let e = wait_for(&sess, |e| matches!(e, SessionEvent::Connected { .. }));
        assert!(
            matches!(
                e,
                SessionEvent::Connected {
                    width: 2,
                    height: 2,
                    encrypted: false,
                    ..
                }
            ),
            "{round}"
        );
        wait_for(&sess, |e| *e == SessionEvent::Updated);
        {
            let f = sess.frame().lock().unwrap();
            assert_eq!(
                f.fb.as_ref().unwrap().pixel(0, 0),
                Some([200, 100, 50, 255])
            );
            assert!(!f.damage.is_empty());
        }
        sess.send(Command::Key(KeyEvent {
            down: true,
            keysym: 0x61,
        }));
        let e = wait_for(&sess, |e| matches!(e, SessionEvent::Disconnected { .. }));
        assert!(matches!(
            e,
            SessionEvent::Disconnected { retrying: true, .. }
        ));
    }
}

#[test]
fn first_connection_failure_is_final() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let sess = Session::spawn(
        rt.handle(),
        ConnectOptions::new("127.0.0.1:1"),
        Arc::new(|| {}),
    );
    let e = wait_for(&sess, |e| matches!(e, SessionEvent::Disconnected { .. }));
    assert!(matches!(
        e,
        SessionEvent::Disconnected {
            retrying: false,
            ..
        }
    ));
}
