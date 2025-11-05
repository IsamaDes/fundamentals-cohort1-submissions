
import * as bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import { hashPassword, comparePassword } from "../../src/util/bycrypt";
import {
  signAccess,
  signRefresh,
  verifyAccess,
  verifyRefresh,
} from "../../src/util/jwt";

jest.mock("bcrypt");
jest.mock("jsonwebtoken");

describe("Password Utils", () => {
  const password = "secret123";
  const hash = "hashed_secret";

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test("hashPassword should hash the password", async () => {
    (bcrypt.hash as jest.Mock).mockResolvedValue(hash);

    const result = await hashPassword(password);
    expect(bcrypt.hash).toHaveBeenCalledWith(password, 10);
    expect(result).toBe(hash);
  });

  test("comparePassword should return true when passwords match", async () => {
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);

    const result = await comparePassword(password, hash);
    expect(bcrypt.compare).toHaveBeenCalledWith(password, hash);
    expect(result).toBe(true);
  });

  test("comparePassword should return false when passwords don't match", async () => {
    (bcrypt.compare as jest.Mock).mockResolvedValue(false);

    const result = await comparePassword(password, hash);
    expect(result).toBe(false);
  });
});

describe("JWT Utils", () => {
  const mockUser = { _id: "12345" };
  const mockJti = "jti_abc";
  const mockAccessToken = "access_token";
  const mockRefreshToken = "refresh_token";
  const mockDecodedAccess = { sub: "12345" };
  const mockDecodedRefresh = { sub: "12345", jti: mockJti };

  beforeEach(() => {
    process.env.ACCESS_TOKEN_SECRET = "access_secret";
    process.env.REFRESH_TOKEN_SECRET = "refresh_secret";
    process.env.ACCESS_TOKEN_EXPIRES = "15m";
    process.env.REFRESH_TOKEN_EXPIRES = "7d";
    jest.clearAllMocks();
  });

  test("signAccess should sign a JWT with the user ID", () => {
    (jwt.sign as jest.Mock).mockReturnValue(mockAccessToken);

    const token = signAccess(mockUser as any);
    expect(jwt.sign).toHaveBeenCalledWith(
      { sub: mockUser._id },
      "access_secret",
      { expiresIn: "15m" }
    );
    expect(token).toBe(mockAccessToken);
  });

  test("signRefresh should sign a refresh JWT with userId and jti", () => {
    (jwt.sign as jest.Mock).mockReturnValue(mockRefreshToken);

    const token = signRefresh(mockUser._id, mockJti);
    expect(jwt.sign).toHaveBeenCalledWith(
      { sub: mockUser._id, jti: mockJti },
      "refresh_secret",
      { expiresIn: "7d" }
    );
    expect(token).toBe(mockRefreshToken);
  });

  test("verifyAccess should return decoded token if valid", () => {
    (jwt.verify as jest.Mock).mockReturnValue(mockDecodedAccess);

    const result = verifyAccess(mockAccessToken);
    expect(jwt.verify).toHaveBeenCalledWith(mockAccessToken, "access_secret");
    expect(result).toEqual(mockDecodedAccess);
  });

  test("verifyAccess should return null if token invalid", () => {
    (jwt.verify as jest.Mock).mockImplementation(() => {
      throw new Error("Invalid token");
    });

    const result = verifyAccess("invalid");
    expect(result).toBeNull();
  });

  test("verifyRefresh should return decoded token if valid", () => {
    (jwt.verify as jest.Mock).mockReturnValue(mockDecodedRefresh);

    const result = verifyRefresh(mockRefreshToken);
    expect(jwt.verify).toHaveBeenCalledWith(mockRefreshToken, "refresh_secret");
    expect(result).toEqual(mockDecodedRefresh);
  });

  test("verifyRefresh should return null if token invalid", () => {
    (jwt.verify as jest.Mock).mockImplementation(() => {
      throw new Error("Invalid token");
    });

    const result = verifyRefresh("invalid");
    expect(result).toBeNull();
  });
});
