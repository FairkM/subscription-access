;; Subscription-Based Access Control
;; Author: YOU
;; Purpose: Grant time-limited access to users who pay STX

;; --- Constants ---
(define-constant admin 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)
(define-constant subscription-duration u262800) ;; 1 month = ~30.44 days in blocks (at ~10s/block)
(define-constant err-unauthorized u401)
(define-constant err-invalid-amount u402)
(define-constant err-user-not-found u404)

;; --- Block Height Function ---
(define-read-only (get-current-block)
  burn-block-height)

;; --- Variables ---
(define-data-var subscription-price uint u1000000) ;; 1 STX in microSTX

(define-map subscriptions
  { subscriber: principal }
  { expires-at: uint }
)

(define-map events
  {
    event-type: (string-ascii 20),
    user: principal,
    block: uint
  }
  {
    expires-at: (optional uint),
    price: (optional uint)
  }
)

;; --- Subscribe (Pay STX to gain access) ---
(define-public (subscribe)
  (let (
        (price (var-get subscription-price))
        (now (get-current-block))
      )
    (try! (stx-transfer? price tx-sender (as-contract tx-sender)))

    (let (
          (current-sub (map-get? subscriptions { subscriber: tx-sender }))
          (new-expiry (if (is-some current-sub)
                         (if (> (get expires-at (unwrap! current-sub (err err-user-not-found))) now)
                             (+ (get expires-at (unwrap! current-sub (err err-user-not-found))) subscription-duration)
                             (+ now subscription-duration))
                         (+ now subscription-duration)))
        )
      (map-set subscriptions { subscriber: tx-sender } { expires-at: new-expiry })
      (map-set events
        { event-type: "subscribe", user: tx-sender, block: now }
        { expires-at: (some new-expiry), price: none })
      (ok { expires-at: new-expiry })
    )
  )
)

;; --- Read Access: Check if user is subscribed ---
(define-read-only (has-access (user principal))
  (let (
        (sub (map-get? subscriptions { subscriber: user }))
        (now (get-current-block))
      )
    (if (is-some sub)
         (ok (> (get expires-at (unwrap! sub (err err-user-not-found))) now))
         (ok false)
    )
  )
)

;; --- Admin: Set New Subscription Price ---
(define-public (set-price (new-price uint))
  (begin
    (asserts! (is-eq tx-sender admin) (err err-unauthorized))
    (asserts! (> new-price u0) (err err-invalid-amount))
    (var-set subscription-price new-price)
    (map-set events
      { event-type: "price-update", user: tx-sender, block: (get-current-block) }
      { expires-at: none, price: (some new-price) })
    (ok new-price)
  )
)

;; --- Admin: Revoke User Subscription ---
(define-public (revoke (target principal))
  (begin
    (asserts! (is-eq tx-sender admin) (err err-unauthorized))
    (let (
          (subscription (map-get? subscriptions { subscriber: target }))
        )
      (asserts! (is-some subscription) (err err-user-not-found))
      (map-delete subscriptions { subscriber: target })
      (map-set events
        { event-type: "revoke", user: target, block: (get-current-block) }
        { expires-at: none, price: none })
      (ok true))
  )
)

;; --- Admin: Withdraw STX from Contract ---
(define-public (withdraw (amount uint))
  (begin
    (asserts! (is-eq tx-sender admin) (err err-unauthorized))
    (asserts! (> amount u0) (err err-invalid-amount))
    (try! (stx-transfer? amount (as-contract tx-sender) admin))
    (ok amount)
  )
)

;; --- Read: Check expiry block ---
(define-read-only (get-expiry (user principal))
  (if (is-some (map-get? subscriptions { subscriber: user }))
      (ok (get expires-at (unwrap! (map-get? subscriptions { subscriber: user }) (err err-user-not-found))))
      (ok u0)
  )
)
