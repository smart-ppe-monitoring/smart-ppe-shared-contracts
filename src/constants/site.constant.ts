export const SITE_STATUS = {
  ACTIVE: "ACTIVE",
  INACTIVE: "INACTIVE",
  COMPLETED: "COMPLETED",
  ARCHIVED: "ARCHIVED",
} as const;

export type SiteStatus = (typeof SITE_STATUS)[keyof typeof SITE_STATUS];

export const ZONE_STATUS = {
  ACTIVE: "ACTIVE",
  INACTIVE: "INACTIVE",
  MAINTENANCE: "MAINTENANCE",
} as const;

export type ZoneStatus = (typeof ZONE_STATUS)[keyof typeof ZONE_STATUS];

export const RESTRICTED_AREA_STATUS = {
  ACTIVE: "ACTIVE",
  INACTIVE: "INACTIVE",
} as const;

export type RestrictedAreaStatus =
  (typeof RESTRICTED_AREA_STATUS)[keyof typeof RESTRICTED_AREA_STATUS];

export const DEFAULT_SAFETY_CONFIG = {
  CONFIDENCE_THRESHOLD: 0.8,
  HELMET_CONFIRMATION_DURATION: 2,
  CONFIRMATION_DURATION: 2,
  VEST_CONFIRMATION_DURATION: 4,
  COOLDOWN_DURATION: 30,
  ENABLE_NO_HELMET: true,
  ENABLE_NO_VEST: true,
  ENABLE_RESTRICTED_AREA: true,

  confidenceThreshold: 0.8,
  helmetConfirmationDuration: 2,
  confirmationDuration: 2,
  vestConfirmationDuration: 4,
  cooldownDuration: 30,
  enableNoHelmet: true,
  enableNoVest: true,
  enableRestrictedArea: true,
} as const;
