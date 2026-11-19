// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import * as React from "react";
import i18next from "i18next";
import {Button} from "@/components/ui/button";
import {Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle} from "@/components/ui/dialog";
import {Input} from "@/components/ui/input";
import {Label} from "@/components/ui/label";
import {CodeInput} from "@/components/auth/CodeInput";
import {EmailMfaType, SmsMfaType, TotpMfaType} from "@/components/auth/mfa/constants";
import * as MfaBackend from "@/backend/MfaBackend";
import * as Setting from "@/lib/setting";

// the factors the step-up check takes: a push or a RADIUS code can't show that it is the user
const StepUpMfaTypes = [TotpMfaType, EmailMfaType, SmsMfaType];

const FactorLabelKeys: Record<string, string> = {
  [TotpMfaType]: "mfa:Use Authenticator App",
  [EmailMfaType]: "mfa:Use Email",
  [SmsMfaType]: "mfa:Use SMS",
};

/** Tells whether an answer asks the user to show a factor first, see MfaBackend.MfaStepUpRequired. */
export function isMfaStepUpRequired(res: any) {
  return res?.status === "error" && res?.data === MfaBackend.MfaStepUpRequired;
}

interface MfaStepUpDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** the user's factors, as get-account or get-user list them */
  mfaItems: any[];
  /** called once a factor passed: the session may now change the factors for a few minutes */
  onSuccess: () => void;
}

/**
 * Asks a user who has a second factor for one before the factors are set up, replaced or removed: the server
 * refuses those changes with "mfa-step-up-required" otherwise, so a stolen session can't swap in another
 * authenticator. A code of an enrolled factor, or a recovery code, is checked with /api/mfa/verify.
 */
export function MfaStepUpDialog({open, onOpenChange, mfaItems, onSuccess}: MfaStepUpDialogProps) {
  const factors = React.useMemo(
    () => (mfaItems ?? []).filter((item: any) => item?.enabled && StepUpMfaTypes.includes(item.mfaType)),
    [mfaItems],
  );
  const [mfaType, setMfaType] = React.useState<string | undefined>(undefined);
  const [passcode, setPasscode] = React.useState("");
  const [recoveryCode, setRecoveryCode] = React.useState("");
  const [useRecovery, setUseRecovery] = React.useState(false);
  const [sending, setSending] = React.useState(false);
  const [verifying, setVerifying] = React.useState(false);

  const selected = factors.find((item: any) => item.mfaType === mfaType) ?? factors.find((item: any) => item.isPreferred) ?? factors[0];

  React.useEffect(() => {
    if (open) {
      setPasscode("");
      setRecoveryCode("");
      setUseRecovery(factors.length === 0);
    }
  }, [open, factors.length]);

  const send = () => {
    if (!selected) {
      return;
    }
    setSending(true);
    MfaBackend.MfaSend({mfaType: selected.mfaType})
      .then((res: any) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("user:Verification code sent"));
        } else {
          Setting.showMessage("error", res.msg);
        }
      })
      .catch((err: any) => Setting.showMessage("error", err.message))
      .finally(() => setSending(false));
  };

  const verify = () => {
    if (verifying) {
      return;
    }
    setVerifying(true);
    const values = useRecovery ? {recoveryCode} : {mfaType: selected?.mfaType, passcode};
    MfaBackend.MfaVerify(values)
      .then((res: any) => {
        if (res.status === "ok") {
          onOpenChange(false);
          onSuccess();
        } else {
          Setting.showMessage("error", res.msg);
        }
      })
      .catch((err: any) => Setting.showMessage("error", err.message))
      .finally(() => setVerifying(false));
  };

  const isCodeType = selected?.mfaType === EmailMfaType || selected?.mfaType === SmsMfaType;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[440px]">
        <DialogHeader>
          <DialogTitle>{i18next.t("mfa:Multi-factor authentication")}</DialogTitle>
          <DialogDescription>{i18next.t("mfa:Please verify your multi-factor authentication before changing it")}</DialogDescription>
        </DialogHeader>
        {useRecovery ? (
          <div className="space-y-2">
            <Label htmlFor="stepUpRecoveryCode">{i18next.t("mfa:Recovery code")}</Label>
            <Input
              id="stepUpRecoveryCode"
              autoFocus
              placeholder={i18next.t("mfa:Recovery code")}
              value={recoveryCode}
              onChange={(e) => setRecoveryCode(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  verify();
                }
              }}
            />
          </div>
        ) : (
          <div className="space-y-3">
            {isCodeType ? (
              <div className="flex justify-between gap-2">
                <span className="truncate text-sm text-muted-foreground">{selected?.secret}</span>
                <Button size="sm" variant="outline" loading={sending} onClick={send}>
                  {i18next.t("code:Get Code")}
                </Button>
              </div>
            ) : null}
            <CodeInput autoFocus value={passcode} onChange={setPasscode} onComplete={verify} />
            {factors.length > 1 ? (
              <div className="flex flex-wrap justify-center gap-1">
                {factors.filter((item: any) => item.mfaType !== selected?.mfaType).map((item: any) => (
                  <Button
                    key={item.mfaType}
                    variant="link"
                    size="sm"
                    onClick={() => {
                      setMfaType(item.mfaType);
                      setPasscode("");
                    }}
                  >
                    {i18next.t(FactorLabelKeys[item.mfaType])}
                  </Button>
                ))}
              </div>
            ) : null}
          </div>
        )}
        <DialogFooter className="gap-2 sm:justify-between">
          {factors.length > 0 ? (
            <Button variant="link" size="sm" onClick={() => setUseRecovery(!useRecovery)}>
              {useRecovery ? i18next.t("mfa:Multi-factor authentication") : i18next.t("mfa:Recovery code")}
            </Button>
          ) : <span />}
          <Button loading={verifying} onClick={verify}>{i18next.t("forget:Verify")}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
